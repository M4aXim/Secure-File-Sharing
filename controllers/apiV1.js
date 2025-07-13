const path = require('path');
const mime = require('mime-types');
const zlib = require('zlib');
const {
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  DeleteObjectCommand
} = require('@aws-sdk/client-s3');

module.exports = async function (fastify, opts) {
  const {
    validateApiKey,
    apiKeysColl,
    foldersColl,
    s3,
    jwt,
    JWT_SECRET,
    generateApiKey,
    logActivity,
    ObjectId,
    COMPRESSION_ENABLED,
    COMPRESSION_THRESHOLD,
    COMPRESSION_LEVEL
  } = opts;

  // GET /api/v1/file/:fileId
  fastify.get('/api/v1/file/:fileId', async (req, reply) => {
    try {
      const { fileId } = req.params;
      const apiKey = req.headers['x-api-key'];
      const range = req.headers.range;

      // Parse file ID with proper URL decoding
      let folderId, filename;
      try {
        const parts = decodeURIComponent(fileId).split(':', 2);
        if (parts.length === 2) {
          [folderId, filename] = parts;
        } else {
          const folderIdPattern = /^[a-f0-9]{32}$/;
          const lastFolderIdIndex = fileId.lastIndexOf('/');
          if (lastFolderIdIndex !== -1) {
            const potentialFolderId = fileId.slice(lastFolderIdIndex + 1, lastFolderIdIndex + 33);
            if (folderIdPattern.test(potentialFolderId)) {
              folderId = potentialFolderId;
              filename = fileId.slice(lastFolderIdIndex + 34);
            }
          }
        }
      } catch (err) {
        fastify.log.warn('Error parsing fileId:', { fileId, error: err.message });
        return reply.code(400).send({ error: 'Invalid file ID format' });
      }

      if (!folderId || !filename) {
        return reply.code(400).send({ error: 'Invalid file ID format' });
      }

      const meta = await foldersColl.findOne({ folderId });
      if (!meta) {
        return reply.code(404).send({ error: 'Folder not found' });
      }

      if (!meta.isPublic) {
        const keyData = await validateApiKey(apiKey);
        if (!keyData) {
          return reply.code(401).send({ error: 'Invalid API key' });
        }

        const hasAccess =
          meta.owner === keyData.username ||
          (meta.permissions &&
            meta.permissions[keyData.username] &&
            meta.permissions[keyData.username].download);

        if (!hasAccess) {
          return reply.code(403).send({ error: 'Access denied' });
        }

        await apiKeysColl.updateOne(
          { _id: keyData._id },
          { $inc: { usageCount: 1 } }
        );
      }

      const key = `folders/${folderId}/${filename}`;
      let headRes;
      try {
        headRes = await s3.send(
          new HeadObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key })
        );
      } catch (err) {
        if (err.name === 'NotFound' || err.name === 'NoSuchKey') {
          try {
            const alternativeKey = `folders/${folderId}/${encodeURIComponent(filename)}`;
            headRes = await s3.send(
              new HeadObjectCommand({
                Bucket: process.env.S3_BUCKET_NAME,
                Key: alternativeKey
              })
            );
          } catch (altErr) {
            fastify.log.error('File not found with both original and encoded filename:', {
              folderId,
              filename,
              error: err.message,
              altError: altErr.message
            });
            return reply.code(404).send({ error: 'File not found' });
          }
        } else {
          throw err;
        }
      }

      const isCompressed = headRes.Metadata?.['is-compressed'] === 'true';
      const originalContentType = headRes.Metadata?.['original-content-type'];

      const mimeType = isCompressed
        ? originalContentType
        : mime.lookup(filename) || 'application/octet-stream';
      const totalSize = headRes.ContentLength;
      const fileExtension = path.extname(filename).toLowerCase();

      const inlineTypes = [
        '.pdf',
        '.jpg',
        '.jpeg',
        '.png',
        '.gif',
        '.svg',
        '.webp',
        '.mp4',
        '.webm',
        '.mp3',
        '.wav'
      ];
      const shouldDisplayInline = inlineTypes.includes(fileExtension);
      const disposition = shouldDisplayInline ? 'inline' : 'attachment';

      let rangeStart = 0;
      let rangeEnd = totalSize - 1;
      let isRangeRequest = false;

      if (range && totalSize > 0) {
        const rangeMatch = /bytes=(\d+)-(\d*)/.exec(range);
        if (rangeMatch) {
          rangeStart = parseInt(rangeMatch[1], 10);
          if (rangeMatch[2]) {
            rangeEnd = Math.min(parseInt(rangeMatch[2], 10), totalSize - 1);
          }

          if (rangeStart >= totalSize || rangeStart > rangeEnd) {
            return reply
              .code(416)
              .header('Content-Range', `bytes */${totalSize}`)
              .send({ error: 'Range not satisfiable' });
          }

          isRangeRequest = true;
        }
      }

      const getObjectParams = {
        Bucket: process.env.S3_BUCKET_NAME,
        Key: key
      };

      if (isRangeRequest) {
        getObjectParams.Range = `bytes=${rangeStart}-${rangeEnd}`;
      }

      const s3Response = await s3.send(new GetObjectCommand(getObjectParams));
      let stream = s3Response.Body;

      stream.on('error', (err) => {
        fastify.log.error('Stream error while serving file:', {
          error: err.message,
          stack: err.stack,
          fileId: req.params.fileId,
          key,
          rangeStart,
          rangeEnd
        });
      });

      if (isCompressed) {
        const gunzip = zlib.createGunzip();
        stream = stream.pipe(gunzip);
      }

      const responseHeaders = {
        'Content-Type': mimeType,
        'Content-Disposition': `${disposition}; filename="${encodeURIComponent(filename)}"`,
        'Cache-Control': 'public, max-age=3600',
        ETag: headRes.ETag,
        'Last-Modified': headRes.LastModified
      };

      if (isRangeRequest) {
        responseHeaders['Accept-Ranges'] = 'bytes';
        responseHeaders['Content-Range'] = `bytes ${rangeStart}-${rangeEnd}/${totalSize}`;
        responseHeaders['Content-Length'] = rangeEnd - rangeStart + 1;
      } else {
        responseHeaders['Content-Length'] = totalSize;
      }

      return reply.code(isRangeRequest ? 206 : 200).headers(responseHeaders).send(stream);
    } catch (err) {
      fastify.log.error('Error serving file:', {
        error: err.message,
        stack: err.stack,
        fileId: req.params.fileId,
        key: `folders/${folderId}/${filename}`,
        s3Error: err.name,
        s3Code: err.$metadata?.httpStatusCode,
        s3RequestId: err.$metadata?.requestId
      });

      if (err.name === 'NoSuchKey' || err.name === 'NotFound') {
        return reply.code(404).send({ error: 'File not found' });
      }

      return reply.code(500).send({ error: 'Failed to serve file' });
    }
  });

  // GET /api/v1/folder/:folderId
  fastify.get('/api/v1/folder/:folderId', async (req, reply) => {
    try {
      const { folderId } = req.params;
      const folder = await foldersColl.findOne({ folderId });
      if (!folder) return reply.notFound('Folder not found');
      return folder;
    } catch (err) {
      fastify.log.error('Error getting folder:', err);
      return reply.internalServerError('Error retrieving folder');
    }
  });

  // GET /api/v1/latest/:folderId
  fastify.get('/api/v1/latest/:folderId', async (req, reply) => {
    const { folderId } = req.params;
    const apiKey = req.headers['x-api-key'];
    const folder = await foldersColl.findOne({ folderId });
    if (!folder) return reply.notFound('Folder not found');

    const keyData = await validateApiKey(apiKey);
    if (!keyData) return reply.code(401).send({ error: 'Invalid API key' });

    if (!folder.isPublic) {
      const hasAccess =
        folder.owner === keyData.username ||
        folder.permissions?.[keyData.username]?.download;
      if (!hasAccess) return reply.forbidden('Access denied');
    }

    const data = await s3.send(
      new ListObjectsV2Command({
        Bucket: process.env.S3_BUCKET_NAME,
        Prefix: `folders/${folderId}/`
      })
    );
    if (!data.Contents?.length) return reply.notFound('No files in folder');

    const latest = data.Contents
      .filter((obj) => obj.Key !== `folders/${folderId}/`)
      .sort((a, b) => b.LastModified - a.LastModified)[0];
    const filename = latest.Key.slice(`folders/${folderId}/`.length);

    await apiKeysColl.updateOne({ _id: keyData._id }, { $inc: { usageCount: 1 } });

    return reply.send({
      id: `${folderId}:${filename}`,
      name: filename,
      size: latest.Size,
      type: mime.lookup(filename) || 'application/octet-stream',
      lastModified: latest.LastModified.toISOString(),
      url: `https://hackclub.maksimmalbasa.in.rs/api/v1/file/${folderId}:${filename}`
    });
  });

  // POST /api/v1/upload
  fastify.post('/api/v1/upload', async (req, reply) => {
    const apiKey = req.headers['x-api-key'];
    const folderId = req.query.folderId;
    if (!folderId) return reply.badRequest('folderId query parameter is required');

    const keyData = await validateApiKey(apiKey);
    if (!keyData) return reply.code(401).send({ error: 'Invalid API key' });

    const folder = await foldersColl.findOne({ folderId });
    if (!folder) return reply.notFound('Folder not found');

    const hasUpload =
      folder.owner === keyData.username || folder.permissions?.[keyData.username]?.upload;
    if (!hasUpload) return reply.forbidden('No upload permission');

    const uploadedFiles = [];
    for await (const file of await req.files()) {
      if (file.file.truncated) return reply.entityTooLarge('File too large');
      const filename = `${Date.now()}-${file.filename}`;
      let fileBuffer = await file.toBuffer();
      let contentType = file.mimetype || mime.lookup(filename) || 'application/octet-stream';
      let contentLength = fileBuffer.length;
      let isCompressed = false;

      if (COMPRESSION_ENABLED && fileBuffer.length >= COMPRESSION_THRESHOLD) {
        try {
          const compressed = await new Promise((resolve, reject) => {
            zlib.gzip(fileBuffer, { level: COMPRESSION_LEVEL }, (err, result) => {
              if (err) reject(err);
              else resolve(result);
            });
          });

          if (compressed.length < fileBuffer.length) {
            fileBuffer = compressed;
            contentType = 'application/gzip';
            contentLength = compressed.length;
            isCompressed = true;
          }
        } catch (err) {
          fastify.log.warn('Compression failed:', err);
        }
      }

      await s3.send(
        new PutObjectCommand({
          Bucket: process.env.S3_BUCKET_NAME,
          Key: `folders/${folderId}/${filename}`,
          Body: fileBuffer,
          ContentType: contentType,
          ContentLength: contentLength,
          Metadata: {
            'original-content-type': file.mimetype || mime.lookup(filename) || 'application/octet-stream',
            'is-compressed': isCompressed.toString()
          }
        })
      );

      uploadedFiles.push({
        id: `${folderId}:${filename}`,
        name: filename,
        size: contentLength,
        type: contentType,
        isCompressed,
        url: `https://hackclub.maksimmalbasa.in.rs/api/v1/file/${folderId}:${filename}`
      });
    }

    await apiKeysColl.updateOne({ _id: keyData._id }, { $inc: { usageCount: 1 } });
    return reply.send({ files: uploadedFiles });
  });

  fastify.delete('/api/v1/delete/:folderId/:filename', async (req, reply) => {
    const { folderId, filename } = req.params;
    const apiKey = req.headers['x-api-key'];
    const keyData = await validateApiKey(apiKey);
    if (!keyData) return reply.code(401).send({ error: 'Invalid API key' });

    const folder = await foldersColl.findOne({ folderId });
    if (!folder) return reply.notFound('Folder not found');

    const hasDelete =
      folder.owner === keyData.username || folder.permissions?.[keyData.username]?.delete;
    if (!hasDelete) return reply.forbidden('Access denied');

    const key = `folders/${folderId}/${filename}`;
    try {
      await s3.send(
        new DeleteObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key })
      );
      return reply.send({ message: 'File deleted' });
    } catch {
      return reply.notFound('File not found');
    }
  });

  // API key management
  fastify.post('/api/v1/keys', async (req, reply) => {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return reply.code(401).send({ error: 'Authentication required' });
      }

      const decoded = jwt.verify(token, JWT_SECRET);
      const { description } = req.body;
      if (!description) {
        return reply.code(400).send({ error: 'Description is required' });
      }

      const key = await generateApiKey(decoded.username, description);
      await logActivity(req, 'generate-api-key', { description });
      return reply.send({ key });
    } catch (err) {
      if (err.name === 'JsonWebTokenError') {
        return reply.code(401).send({ error: 'Invalid token' });
      }
      throw err;
    }
  });

  fastify.get('/api/v1/keys', async (req, reply) => {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return reply.code(401).send({ error: 'Authentication required' });
      }

      const decoded = jwt.verify(token, JWT_SECRET);
      const keys = await apiKeysColl
        .find({ username: decoded.username, isActive: true }, { projection: { key: 0 } })
        .toArray();
      return reply.send({ keys });
    } catch (err) {
      if (err.name === 'JsonWebTokenError') {
        return reply.code(401).send({ error: 'Invalid token' });
      }
      throw err;
    }
  });

  fastify.delete('/api/v1/keys/:keyId', async (req, reply) => {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return reply.code(401).send({ error: 'Authentication required' });
      }

      const decoded = jwt.verify(token, JWT_SECRET);
      const { keyId } = req.params;
      const result = await apiKeysColl.updateOne(
        { _id: new ObjectId(keyId), username: decoded.username, isActive: true },
        { $set: { isActive: false } }
      );
      if (result.matchedCount === 0) {
        return reply.code(404).send({ error: 'API key not found' });
      }

      await logActivity(req, 'revoke-api-key', { keyId });
      return reply.send({ success: true });
    } catch (err) {
      if (err.name === 'JsonWebTokenError') {
        return reply.code(401).send({ error: 'Invalid token' });
      }
      throw err;
    }
  });

  fastify.get('/api/v1/usage', async (req, reply) => {
    const apiKey = req.headers['x-api-key'];
    const keyData = await validateApiKey(apiKey);
    if (!keyData) return reply.code(401).send({ error: 'Invalid API key' });

    const userFolders = await foldersColl.find({ owner: keyData.username }).toArray();
    let totalSize = 0,
      totalFiles = 0;
    for (const folder of userFolders) {
      const data = await s3.send(
        new ListObjectsV2Command({
          Bucket: process.env.S3_BUCKET_NAME,
          Prefix: `folders/${folder.folderId}/`
        })
      );
      const contents = data.Contents || [];
      totalFiles += contents.length;
      totalSize += contents.reduce((sum, obj) => sum + obj.Size, 0);
    }

    await apiKeysColl.updateOne({ _id: keyData._id }, { $inc: { usageCount: 1 } });
    return reply.send({
      apiKey: {
        created: keyData.created,
        lastUsed: keyData.lastUsed,
        totalRequests: keyData.usageCount
      },
      storage: {
        files: totalFiles,
        totalSize
      }
    });
  });
};

