const p = new URLSearchParams(window.location.search);
const folderID = p.get('folderID');
const filename = p.get('filename');

if (!folderID || !filename) {
  document.body.innerHTML = '<p class="msg">Missing folderID or filename.</p>';
  throw 'Missing params';
}

const ext = filename.split('.').pop().toLowerCase();

if (ext === 'mp4') {
  window.location.replace(
    `mp4.html?folderID=${encodeURIComponent(folderID)}&filename=${encodeURIComponent(filename)}`
  );
} else if (ext === 'mp3') {
  window.location.replace(
    `mp3.html?folderID=${encodeURIComponent(folderID)}&filename=${encodeURIComponent(filename)}`
  );
} else if (ext === 'docx') {
  window.location.replace(
    `/view/word.html?folderID=${encodeURIComponent(folderID)}&filename=${encodeURIComponent(filename)}`
  );
} else if (ext === 'pdf') {
  const fileURL = `/api/view-file/${folderID}/${encodeURIComponent(filename)}`;
  // Get JWT token from localStorage 
  const jwtToken = localStorage.getItem('jwtToken');
  
  // Open PDF in a new window with authorization
  const pdfWindow = window.open('', '_blank');
  fetch(fileURL, {
    headers: {
      'Authorization': `Bearer ${jwtToken}`
    }
  })
  .then(response => response.blob())
  .then(blob => {
    const objectUrl = URL.createObjectURL(blob);
    pdfWindow.location.href = objectUrl;
  })
  .catch(error => {
    console.error('Error fetching PDF:', error);
    pdfWindow.close();
    alert('Failed to load PDF file');
  });
} else {
  // Attempt to fetch and display in blob
  const viewURL = `/api/view-file/${folderID}/${encodeURIComponent(filename)}`;
  fetch(viewURL)
    .then(async res => {
      if (!res.ok) throw new Error('Fetch failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);

      const iframe = document.createElement('iframe');
      iframe.style.width = '100%';
      iframe.style.height = '100vh';
      iframe.src = url;
      iframe.onload = () => URL.revokeObjectURL(url);

      document.body.innerHTML = '';
      document.body.appendChild(iframe);
    })
    .catch(err => {
      console.warn('Blob render failed, falling back to download:', err);
      const downloadURL = `/api/unable-to-load/download-file?folderId=${encodeURIComponent(folderID)}&filename=${encodeURIComponent(filename)}`;
      const a = document.createElement('a');
      a.href = downloadURL;
      a.download = filename;
      document.body.innerHTML = `<div class="msg">File not viewable, downloading: <strong>${filename}</strong></div>`;
      document.body.appendChild(a);
      a.click();
    });
}
