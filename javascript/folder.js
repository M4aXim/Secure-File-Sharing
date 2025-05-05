document.addEventListener('DOMContentLoaded', async () => {
    const token       = localStorage.getItem('jwtToken');
    const urlParams   = new URLSearchParams(window.location.search);
    const folderId    = urlParams.get('folderID');
    if (!folderId) {
      window.location.href = '/dashboard.html';
      return;
    }
    folderIdSpan.textContent = folderId;

    // 1) Check if the folder is public
    let isPublic = false;
    try {
      const publicCheckRes = await fetch(`/api/is-folder-public/${folderId}`);
      const publicData     = await publicCheckRes.json();
      isPublic = publicData.isPublic;
    } catch (err) {
      console.error('Public check failed', err);
    }

    // 2) If not public, require authentication & token verification
    if (!isPublic) {
      if (!token) {
        window.location.href = '/index.html';
        return;
      }
      try {
        const verifyRes = await fetch('/api/verify-token', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!verifyRes.ok) {
          localStorage.removeItem('jwtToken');
          window.location.href = '/index.html';
          return;
        }
      } catch (err) {
        console.error('Token verify failed', err);
        localStorage.removeItem('jwtToken');
        window.location.href = '/index.html';
        return;
      }
    }

    // 3) After passing public/auth check, load folder contents & ownership
    checkOwnership();
    fetchFolderContents();
  });

  // DOM refs
  const fileInput              = document.getElementById('fileInput');
  const fileNameDisplay        = document.getElementById('fileName');
  const uploadButton           = document.getElementById('uploadButton');
  const dropZone               = document.getElementById('dropZone');
  const folderContentsDiv      = document.getElementById('folderContents');
  const folderIdSpan           = document.getElementById('folderId');
  const progressContainer      = document.getElementById('progressContainer');
  const uploadProgress         = document.getElementById('uploadProgress');
  const progressText           = document.getElementById('progressText');
  const loadingSpinner         = document.getElementById('loadingSpinner');
  const refreshButton          = document.getElementById('refreshButton');
  const searchInput            = document.getElementById('searchInput');
  const notification           = document.getElementById('notificationSuccess');
  const notificationText       = document.getElementById('notificationText');
  const closeNotification      = document.getElementById('closeNotification');
  const changePermissionButton = document.getElementById('changePermissionButton');
  const makePublicButton       = document.getElementById('makePublicButton');

  // Helpers
  function formatFileSize(bytes) {
    if (!bytes) return '0 Bytes';
    const k = 1024,
          sizes = ['Bytes','KB','MB','GB','TB'],
          i = Math.floor(Math.log(bytes)/Math.log(k));
    return `${(bytes/Math.pow(k,i)).toFixed(2)} ${sizes[i]}`;
  }
  function formatDate(d) {
    return new Date(d).toLocaleString();
  }
  function getFileIcon(ext) {
    const icons = {
      '.pdf':'fa-file-pdf','.doc':'fa-file-word','.docx':'fa-file-word',
      '.xls':'fa-file-excel','.xlsx':'fa-file-excel','.ppt':'fa-file-powerpoint',
      '.pptx':'fa-file-powerpoint','.jpg':'fa-file-image','.jpeg':'fa-file-image',
      '.png':'fa-file-image','.gif':'fa-file-image','.txt':'fa-file-alt',
      '.zip':'fa-file-archive','.rar':'fa-file-archive','.mp3':'fa-file-audio',
      '.mp4':'fa-file-video','.html':'fa-file-code','.css':'fa-file-code',
      '.js':'fa-file-code'
    };
    return icons[ext.toLowerCase()] || 'fa-file';
  }
  function showNotification(msg, type = 'is-success') {
    notification.className = `notification ${type}`;
    notificationText.textContent = msg;
    notification.classList.add('show');
    setTimeout(() => notification.classList.remove('show'), 5000);
  }
  closeNotification.addEventListener('click', () => {
    notification.classList.remove('show');
  });

  // Fetch & render folder contents
  async function fetchFolderContents() {
    const token = localStorage.getItem('jwtToken');
    // (no unconditional redirect here — initial check already took care of auth/public)
    const folderId = folderIdSpan.textContent;

    loadingSpinner.style.display = 'block';
    folderContentsDiv.innerHTML = '';

    try {
      const res = await fetch(`/api/folder-contents?folderID=${encodeURIComponent(folderId)}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const contents = await res.json();
      loadingSpinner.style.display = 'none';

      if (!res.ok) {
        return folderContentsDiv.innerHTML = `<div class="notification is-warning">${contents.message||'Error loading'}</div>`;
      }
      if (contents.length === 0) {
        return folderContentsDiv.innerHTML = `
          <div class="empty-folder">
            <i class="fas fa-folder-open fa-3x mb-3" style="color:#ddd"></i>
            <p>This folder is empty</p>
            <p class="is-size-7 has-text-grey">Upload files to get started</p>
          </div>`;
      }

      const fileItems = contents.map((f,i) => {
        const name = f.filename||`File${i}`, ext = f.type||'', size = formatFileSize(f.size), mod = formatDate(f.lastModified);
        return `
          <div class="file-item">
            <div class="file-icon">
              <i class="fas ${getFileIcon(ext)}"></i>
            </div>
            <div class="file-info">
              <span class="file-name">${name}</span>
              <div class="file-meta">
                <span class="file-size">${size}</span>
                <span class="file-date">${mod}</span>
              </div>
            </div>
            <div class="file-actions">
              <button class="button is-small is-info download-button" data-filename="${name}">
                <span class="icon"><i class="fas fa-download"></i></span>
              </button>
              <button class="button is-small is-primary view-button"    data-filename="${name}">
                <span class="icon"><i class="fas fa-eye"></i></span>
              </button>
              <button class="button is-small is-danger delete-button"  data-filename="${name}">
                <span class="icon"><i class="fas fa-trash-alt"></i></span>
              </button>
            </div>
          </div>`;
      }).join('');

      folderContentsDiv.innerHTML = fileItems;

      document.querySelectorAll('.download-button').forEach(btn =>
        btn.addEventListener('click', () => downloadFile(btn.dataset.filename))
      );
      document.querySelectorAll('.view-button').forEach(btn =>
        btn.addEventListener('click', () => viewFile(btn.dataset.filename))
      );
      document.querySelectorAll('.delete-button').forEach(btn =>
        btn.addEventListener('click', () => deleteFile(btn.dataset.filename))
      );

    } catch (err) {
      loadingSpinner.style.display = 'none';
      console.error(err);
      folderContentsDiv.innerHTML = `<div class="notification is-danger">Error: ${err.message}</div>`;
    }
  }

  // Download
  async function downloadFile(filename) {
    const token = localStorage.getItem('jwtToken');
    const folderId = folderIdSpan.textContent;
    try {
      const tRes = await fetch(`/api/generate-download-token?folderID=${encodeURIComponent(folderId)}&filename=${encodeURIComponent(filename)}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!tRes.ok) throw new Error('No download token');
      const { token: dl } = await tRes.json();

      const dlRes = await fetch(`/api/download-file?token=${dl}`);
      if (!dlRes.ok) throw new Error(dlRes.statusText);
      const blob = await dlRes.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showNotification(`Downloaded ${filename}`);
    } catch (err) {
      console.error(err);
      showNotification(`Download failed: ${err.message}`, 'is-danger');
    }
  }

  // View file
  function viewFile(filename) {
    const folderId = folderIdSpan.textContent;
    window.location.href =
      `media_view-redarector.html?folderID=${encodeURIComponent(folderId)}&filename=${encodeURIComponent(filename)}`;
  }

  // Delete
  async function deleteFile(filename) {
    const token = localStorage.getItem('jwtToken');
    const folderId = folderIdSpan.textContent;
    if (!confirm(`Delete ${filename}?`)) return;

    try {
      const res = await fetch(`/api/delete-file/${encodeURIComponent(folderId)}/${encodeURIComponent(filename)}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || res.statusText);

      showNotification(data.message || 'Deleted');
      fetchFolderContents();
    } catch (err) {
      console.error(err);
      showNotification(`Delete failed: ${err.message}`, 'is-danger');
    }
  }

  // Upload
  async function uploadFile() {
    const token = localStorage.getItem('jwtToken');
    const file  = fileInput.files[0];
    const folderId = folderIdSpan.textContent;
    if (!file) return showNotification('Select a file first', 'is-warning');

    const form = new FormData();
    form.append('file', file);
    uploadButton.classList.add('is-loading');
    progressContainer.style.display = 'block';

    const xhr = new XMLHttpRequest();
    xhr.upload.addEventListener('progress', e => {
      if (e.lengthComputable) {
        const pct = Math.round(e.loaded / e.total * 100);
        uploadProgress.value = pct;
        progressText.textContent = pct + '%';
      }
    });
    xhr.onload = () => {
      uploadButton.classList.remove('is-loading');
      progressContainer.style.display = 'none';
      if (xhr.status === 200) {
        showNotification('Uploaded successfully');
        fetchFolderContents();
      } else {
        const err = JSON.parse(xhr.responseText);
        showNotification(err.message || 'Upload error', 'is-danger');
      }
      fileInput.value = '';
      fileNameDisplay.textContent = 'No file selected';
      uploadButton.disabled = true;
      uploadProgress.value = 0;
      progressText.textContent = '0%';
    };
    xhr.onerror = () => {
      uploadButton.classList.remove('is-loading');
      progressContainer.style.display = 'none';
      showNotification('Network error', 'is-danger');
    };
    xhr.open('POST', `/api/upload-file/${encodeURIComponent(folderId)}`, true);
    xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    xhr.send(form);
  }

  // UI handlers
  fileInput.addEventListener('change', () => {
    const f = fileInput.files[0];
    fileNameDisplay.textContent = f ? f.name : 'No file selected';
    uploadButton.disabled = !f;
  });
  uploadButton.addEventListener('click', uploadFile);
  refreshButton.addEventListener('click', fetchFolderContents);

  ['dragenter','dragover','dragleave','drop'].forEach(ev =>
    dropZone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); }, false)
  );
  ['dragenter','dragover'].forEach(ev =>
    dropZone.addEventListener(ev, () => dropZone.classList.add('active'), false)
  );
  ['dragleave','drop'].forEach(ev =>
    dropZone.addEventListener(ev, () => dropZone.classList.remove('active'), false)
  );
  dropZone.addEventListener('drop', e => {
    const files = e.dataTransfer.files;
    if (files.length) {
      fileInput.files = files;
      fileNameDisplay.textContent = files[0].name;
      uploadButton.disabled = false;
    }
  });

  // Add Friend
  document.getElementById('addFriendButton').addEventListener('click', async () => {
    const friendEmail = prompt('Enter the email of the user you want to invite:');
    if (!friendEmail) return;
    const token = localStorage.getItem('jwtToken');
    const folderId = folderIdSpan.textContent;
    try {
      const res = await fetch('/api/add-friend', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ friendEmail, folderId })
      });
      const data = await res.json();
      if (res.ok) showNotification(data.message || 'Invitation sent!');
      else        showNotification(data.message || 'Failed', 'is-danger');
    } catch (err) {
      console.error(err);
      showNotification('Error sending invitation.', 'is-danger');
    }
  });

  // Search filter
  searchInput.addEventListener('input', () => {
    const term = searchInput.value.toLowerCase();
    document.querySelectorAll('.file-item').forEach(item => {
      const name = item.querySelector('.file-name').textContent.toLowerCase();
      item.style.display = name.includes(term) ? 'flex' : 'none';
    });
  });

  // Permission modal code
  const permissionModal          = document.getElementById('permissionModal');
  const permissionModalBody      = document.getElementById('permissionModalBody');
  const savePermissionsButton    = document.getElementById('savePermissionsButton');
  const closePermissionModalBtns = [
    document.getElementById('closePermissionModal'),
    document.getElementById('closePermissionModalFooter')
  ];
  let localPermissions = {};

  async function openPermissionModal() {
    const token = localStorage.getItem('jwtToken');
    const folderId = folderIdSpan.textContent;
    try {
      const [friendsRes, permsRes] = await Promise.all([
        fetch(`/api/show-friends/${encodeURIComponent(folderId)}`,               { headers:{ 'Authorization': `Bearer ${token}` }}),
        fetch(`/api/folders/${encodeURIComponent(folderId)}/friends/permissions`,{ headers:{ 'Authorization': `Bearer ${token}` }})
      ]);
      const friendsData = await friendsRes.json();
      const permsData   = await permsRes.json();
      const friendsList = friendsData.friends || [];
      const permsMap    = {};
      (permsData.friends || []).forEach(f => permsMap[f.username] = f.permissions);

      localPermissions = {};
      let tableHtml = `<table class="table is-fullwidth"><thead><tr>
        <th>Friend</th><th>Download</th><th>Upload</th><th>Delete</th><th>Add Users</th>
      </tr></thead><tbody>`;

      friendsList.forEach(username => {
        const p = permsMap[username] || { download:false, upload:false, delete:false, addUsers:false };
        localPermissions[username] = { ...p };
        tableHtml += `<tr>
          <td>${username}</td>
          <td><button class="button is-small permission-toggle" data-username="${username}" data-perm="download">${p.download?'✅':'❌'}</button></td>
          <td><button class="button is-small permission-toggle" data-username="${username}" data-perm="upload">${p.upload?'✅':'❌'}</button></td>
          <td><button class="button is-small permission-toggle" data-username="${username}" data-perm="delete">${p.delete?'✅':'❌'}</button></td>
          <td><button class="button is-small permission-toggle" data-username="${username}" data-perm="addUsers">${p.addUsers?'✅':'❌'}</button></td>
        </tr>`;
      });

      tableHtml += `</tbody></table>`;
      permissionModalBody.innerHTML = tableHtml;
      permissionModalBody.querySelectorAll('.permission-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
          const user = btn.dataset.username;
          const perm = btn.dataset.perm;
          localPermissions[user][perm] = !localPermissions[user][perm];
          btn.textContent = localPermissions[user][perm] ? '✅' : '❌';
        });
      });

      permissionModal.classList.add('is-active');
    } catch (err) {
      console.error('Error loading permissions', err);
      showNotification('Failed to load permissions', 'is-danger');
    }
  }

  function closePermissionModal() {
    permissionModal.classList.remove('is-active');
  }

  async function savePermissions() {
    const token = localStorage.getItem('jwtToken');
    const folderId = folderIdSpan.textContent;
    savePermissionsButton.classList.add('is-loading');
    try {
      for (const username in localPermissions) {
        await fetch(`/api/folders/${encodeURIComponent(folderId)}/friends/${encodeURIComponent(username)}/permissions`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify(localPermissions[username])
        });
      }
      showNotification('Permissions updated successfully');
      permissionModal.classList.remove('is-active');
    } catch (err) {
      console.error('Error saving permissions', err);
      showNotification('Failed to save permissions', 'is-danger');
    } finally {
      savePermissionsButton.classList.remove('is-loading');
    }
  }

  closePermissionModalBtns.forEach(btn => btn.addEventListener('click', closePermissionModal));
  changePermissionButton.addEventListener('click', openPermissionModal);

  // Make Public button handler
  makePublicButton.addEventListener('click', async () => {
    const token = localStorage.getItem('jwtToken');
    const folderId = folderIdSpan.textContent;
    makePublicButton.classList.add('is-loading');
    try {
      const res = await fetch(`/api/make-my-folder-public/${encodeURIComponent(folderId)}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type':  'application/json'
        },
        body: JSON.stringify({})
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || res.statusText);
      showNotification(data.message || 'Folder made public');
      makePublicButton.disabled = true;
    } catch (err) {
      console.error('Error making folder public', err);
      showNotification(`Error: ${err.message}`, 'is-danger');
    } finally {
      makePublicButton.classList.remove('is-loading');
    }
  });

  // Check ownership to hide owner-only buttons
  async function checkOwnership() {
    const token = localStorage.getItem('jwtToken');
    const folderId = folderIdSpan.textContent;
    try {
      const res = await fetch(`/api/am-I-owner-of-folder/${encodeURIComponent(folderId)}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error('Not authorized');
      const { isOwner } = await res.json();
      if (!isOwner) {
        changePermissionButton.style.display = 'none';
        makePublicButton.style.display       = 'none';
      }
    } catch (err) {
      console.error('Ownership check failed', err);
    }
  }