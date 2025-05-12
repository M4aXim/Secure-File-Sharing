// Global variables
let isGridView = localStorage.getItem('gridView') === 'true';
let isOwner = false;
let currentTempLinkFilename = '';

document.addEventListener('DOMContentLoaded', async () => {
  const token       = localStorage.getItem('jwtToken');
  const urlParams   = new URLSearchParams(window.location.search);
  const folderId    = urlParams.get('folderID');
  if (!folderId) {
    window.location.href = '/dashboard.html';
    return;
  }
  
  // Get DOM references
  const folderIdSpan = document.getElementById('folderId');
  if (folderIdSpan) {
    folderIdSpan.textContent = folderId;
  } else {
    console.error('Element with ID "folderId" not found in the document');
  }

  // Initialize view mode
  updateViewMode();

  // Add view toggle handler
  const toggleViewButton = document.getElementById('toggleViewButton');
  if (toggleViewButton) {
    toggleViewButton.addEventListener('click', () => {
      isGridView = !isGridView;
      localStorage.setItem('gridView', isGridView);
      updateViewMode();
      fetchFolderContents();
    });
  }

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

  // Add event listener for export button
  const exportZipButton = document.getElementById('exportZipButton');
  if (exportZipButton) {
    exportZipButton.addEventListener('click', exportAsZip);
  }
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
const tempLinkModal          = document.getElementById('tempLinkModal');
const tempLinkFilename       = document.getElementById('tempLinkFilename');
const tempLinkDuration       = document.getElementById('tempLinkDuration');
const tempLinkResult         = document.getElementById('tempLinkResult');
const tempLinkUrl            = document.getElementById('tempLinkUrl');
const generateTempLinkButton = document.getElementById('generateTempLinkButton');
const copyTempLinkButton     = document.getElementById('copyTempLink');
const closeTempLinkModal     = document.getElementById('closeTempLinkModal');
const closeTempLinkModalFooter = document.getElementById('closeTempLinkModalFooter');

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
  if (!notification || !notificationText) {
    console.error('Notification elements not found');
    return;
  }
  
  notification.className = `notification ${type}`;
  notificationText.textContent = msg;
  notification.classList.add('show');
  setTimeout(() => notification.classList.remove('show'), 5000);
}

if (closeNotification) {
  closeNotification.addEventListener('click', () => {
    if (notification) notification.classList.remove('show');
  });
}

// Add this new function
function updateViewMode() {
  const toggleButton = document.getElementById('toggleViewButton');
  const folderContentsElement = document.getElementById('folderContents');
  
  if (!toggleButton || !folderContentsElement) {
    console.error('Toggle button or folder contents element not found');
    return;
  }
  
  const icon = toggleButton.querySelector('.icon i');
  const text = toggleButton.querySelector('span:not(.icon)');
  
  if (!icon || !text) {
    console.error('Icon or text element not found in toggle button');
    return;
  }
  
  if (isGridView) {
    icon.className = 'fas fa-list';
    text.textContent = 'List View';
    folderContentsElement.className = 'grid-view';
  } else {
    icon.className = 'fas fa-th-large';
    text.textContent = 'Grid View';
    folderContentsElement.className = 'list-view';
  }
}

// Add this helper function at the top level
async function getThumbnailUrl(folderId, filename) {
  const token = localStorage.getItem('jwtToken');
  const response = await fetch(`/api/thumbnail/${folderId}/${encodeURIComponent(filename)}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (!response.ok) throw new Error('Failed to load thumbnail');
  return URL.createObjectURL(await response.blob());
}

// Fetch & render folder contents
async function fetchFolderContents() {
  const token = localStorage.getItem('jwtToken');
  
  // Get folder ID from URL params instead of relying on DOM element
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId) {
    console.error('No folder ID found in URL');
    return;
  }

  if (loadingSpinner) loadingSpinner.style.display = 'block';
  if (folderContentsDiv) folderContentsDiv.innerHTML = '';

  try {
    const res = await fetch(`/api/folder-contents?folderID=${encodeURIComponent(folderId)}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const contents = await res.json();
    if (loadingSpinner) loadingSpinner.style.display = 'none';

    if (!res.ok) {
      if (folderContentsDiv) folderContentsDiv.innerHTML = `<div class="notification is-warning">${contents.message||'Error loading'}</div>`;
      return;
    }
    if (contents.length === 0) {
      if (folderContentsDiv) folderContentsDiv.innerHTML = `
        <div class="empty-folder">
          <i class="fas fa-folder-open fa-3x mb-3" style="color:#ddd"></i>
          <p>This folder is empty</p>
          <p class="is-size-7 has-text-grey">Upload files to get started</p>
        </div>`;
      return;
    }

    const fileItems = contents.map((f,i) => {
      const name = f.filename||`File${i}`;
      const ext = f.type||'';
      const size = formatFileSize(f.size);
      const mod = formatDate(f.lastModified);
      const isImage = /\.(jpg|jpeg|png|gif|webp)$/i.test(name);
      const isVideo = /\.(mp4|webm|mov)$/i.test(name);
      const hasThumbnail = isImage || isVideo;

      if (isGridView) {
        return `
          <div class="grid-item">
            <div class="thumbnail-container">
              ${hasThumbnail ? 
                `<img class="thumbnail" data-folder="${folderId}" data-filename="${name}" alt="${name}" loading="lazy">` :
                `<div class="thumbnail-placeholder"><i class="fas ${getFileIcon(ext)}"></i></div>`
              }
            </div>
            <div class="file-name">${name}</div>
            <div class="file-meta">
              <div>${size}</div>
              <div>${mod}</div>
            </div>
            <div class="file-actions">
              <button class="button is-small is-info download-button" data-filename="${name}">
                <span class="icon"><i class="fas fa-download"></i></span>
              </button>
              <button class="button is-small is-primary view-button" data-filename="${name}">
                <span class="icon"><i class="fas fa-eye"></i></span>
              </button>
              <button class="button is-small is-danger delete-button" data-filename="${name}">
                <span class="icon"><i class="fas fa-trash-alt"></i></span>
              </button>
              ${isOwner ? `
              <button class="button is-small is-warning temp-link-button" data-filename="${name}">
                <span class="icon"><i class="fas fa-link"></i></span>
              </button>
              ` : ''}
            </div>
          </div>`;
      } else {
        return `
          <div class="file-item">
            <div class="file-icon">
              ${hasThumbnail ? 
                `<img class="thumbnail" data-folder="${folderId}" data-filename="${name}" alt="${name}" style="width: 40px; height: 40px; object-fit: cover; border-radius: 4px;">` :
                `<i class="fas ${getFileIcon(ext)}"></i>`
              }
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
              <button class="button is-small is-primary view-button" data-filename="${name}">
                <span class="icon"><i class="fas fa-eye"></i></span>
              </button>
              <button class="button is-small is-danger delete-button" data-filename="${name}">
                <span class="icon"><i class="fas fa-trash-alt"></i></span>
              </button>
              ${isOwner ? `
              <button class="button is-small is-warning temp-link-button" data-filename="${name}" title="Generate temporary link">
                <span class="icon"><i class="fas fa-link"></i></span>
              </button>
              ` : ''}
            </div>
          </div>`;
      }
    }).join('');

    folderContentsDiv.innerHTML = fileItems;

    // Load thumbnails for all thumbnail images
    document.querySelectorAll('.thumbnail').forEach(img => {
      const folderId = img.dataset.folder;
      const filename = img.dataset.filename;
      getThumbnailUrl(folderId, filename)
        .then(url => {
          img.src = url;
        })
        .catch(err => {
          console.error('Failed to load thumbnail:', err);
          img.src = ''; // Clear the src to show the placeholder
        });
    });

    // We no longer need to add individual event handlers here since we're using event delegation
  } catch (err) {
    console.error('Error loading folder contents:', err);
    loadingSpinner.style.display = 'none';
    folderContentsDiv.innerHTML = `
      <div class="notification is-danger">
        Failed to load folder contents. Please try again later.
      </div>
    `;
  }
}

// Download
async function downloadFile(filename) {
  const token = localStorage.getItem('jwtToken');
  
  // Get folder ID from URL params
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId) {
    showNotification('Folder ID not found', 'is-danger');
    return;
  }
  
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
  // Get folder ID from URL params
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId) {
    showNotification('Folder ID not found', 'is-danger');
    return;
  }
  
  window.location.href =
    `media_view-redarector.html?folderID=${encodeURIComponent(folderId)}&filename=${encodeURIComponent(filename)}`;
}

// Delete
async function deleteFile(filename) {
  const token = localStorage.getItem('jwtToken');
  
  // Get folder ID from URL params
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId) {
    showNotification('Folder ID not found', 'is-danger');
    return;
  }
  
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
  
  if (!fileInput) {
    console.error('File input element not found');
    return;
  }
  
  const file = fileInput.files[0];
  
  // Get folder ID from URL params
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId) {
    showNotification('Folder ID not found', 'is-danger');
    return;
  }
  
  if (!file) return showNotification('Select a file first', 'is-warning');

  const form = new FormData();
  form.append('file', file);
  
  if (uploadButton) uploadButton.classList.add('is-loading');
  if (progressContainer) progressContainer.style.display = 'block';

  const xhr = new XMLHttpRequest();
  xhr.upload.addEventListener('progress', e => {
    if (e.lengthComputable && uploadProgress && progressText) {
      const pct = Math.round(e.loaded / e.total * 100);
      uploadProgress.value = pct;
      progressText.textContent = pct + '%';
    }
  });
  xhr.onload = () => {
    if (uploadButton) uploadButton.classList.remove('is-loading');
    if (progressContainer) progressContainer.style.display = 'none';
    if (xhr.status === 200) {
      showNotification('Uploaded successfully');
      fetchFolderContents();
    } else {
      const err = JSON.parse(xhr.responseText);
      showNotification(err.message || 'Upload error', 'is-danger');
    }
    if (fileInput) fileInput.value = '';
    if (fileNameDisplay) fileNameDisplay.textContent = 'No file selected';
    if (uploadButton) uploadButton.disabled = true;
    if (uploadProgress) uploadProgress.value = 0;
    if (progressText) progressText.textContent = '0%';
  };
  xhr.onerror = () => {
    if (uploadButton) uploadButton.classList.remove('is-loading');
    if (progressContainer) progressContainer.style.display = 'none';
    showNotification('Network error', 'is-danger');
  };
  xhr.open('POST', `/api/upload-file/${encodeURIComponent(folderId)}`, true);
  xhr.setRequestHeader('Authorization', `Bearer ${token}`);
  xhr.send(form);
}

// UI handlers
if (fileInput) {
  fileInput.addEventListener('change', () => {
    const f = fileInput.files[0];
    if (fileNameDisplay) fileNameDisplay.textContent = f ? f.name : 'No file selected';
    if (uploadButton) uploadButton.disabled = !f;
  });
}

if (uploadButton) {
  uploadButton.addEventListener('click', uploadFile);
}

if (refreshButton) {
  refreshButton.addEventListener('click', fetchFolderContents);
}

if (dropZone) {
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
    if (files.length && fileInput) {
      fileInput.files = files;
      if (fileNameDisplay) fileNameDisplay.textContent = files[0].name;
      if (uploadButton) uploadButton.disabled = false;
    }
  });
}

// Add Friend button
const addFriendButton = document.getElementById('addFriendButton');
if (addFriendButton) {
  addFriendButton.addEventListener('click', async () => {
    const friendEmail = prompt('Enter the email of the user you want to invite:');
    if (!friendEmail) return;
    
    const token = localStorage.getItem('jwtToken');
    const urlParams = new URLSearchParams(window.location.search);
    const folderId = urlParams.get('folderID');
    
    if (!folderId) {
      showNotification('Folder ID not found', 'is-danger');
      return;
    }
    
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
}

// Search filter
if (searchInput) {
  searchInput.addEventListener('input', () => {
    const term = searchInput.value.toLowerCase();
    document.querySelectorAll('.file-item').forEach(item => {
      const name = item.querySelector('.file-name').textContent.toLowerCase();
      item.style.display = name.includes(term) ? 'flex' : 'none';
    });
  });
}

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

// Make Public/Private button handler
// Make Public/Private button handler
makePublicButton.addEventListener('click', async () => {
  const token = localStorage.getItem('jwtToken');
  
  // Get folder ID from URL params
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId) {
    showNotification('Folder ID not found', 'is-danger');
    return;
  }
  
  try {
    const response = await fetch(`/api/make-my-folder-public/${folderId}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Failed to make folder public');
    }
    
    showNotification('Folder is now public', 'is-success');
    updatePublicButtonText();
  } catch (error) {
    console.error('Error making folder public:', error);
    showNotification('Failed to make folder public', 'is-danger');
  }
});

// Check ownership to hide owner-only buttons
async function checkOwnership() {
  const token = localStorage.getItem('jwtToken');
  
  // Get folder ID from URL params instead of relying on DOM element
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId) {
    console.error('No folder ID found in URL');
    return;
  }
  
  try {
    const response = await fetch(`/api/am-I-owner-of-folder/${folderId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error('Failed to check ownership');
    }
    
    const data = await response.json();
    isOwner = data.isOwner;
    
    // Show/hide owner-only buttons
    if (changePermissionButton) changePermissionButton.style.display = isOwner ? 'flex' : 'none';
    if (makePublicButton) makePublicButton.style.display = isOwner ? 'flex' : 'none';
    if (addFriendButton) addFriendButton.style.display = isOwner ? 'flex' : 'none';
    if (exportZipButton) exportZipButton.style.display = isOwner ? 'inline-flex' : 'none';
    
    // Update button text based on public status
    updatePublicButtonText();
  } catch (error) {
    console.error('Error checking ownership:', error);
    isOwner = false;
  }
}

// Add event listeners after loading folder contents
if (folderContentsDiv) {
  folderContentsDiv.addEventListener('click', (e) => {
    const target = e.target.closest('.download-button, .view-button, .delete-button, .temp-link-button');
    if (!target) return;

    const filename = target.dataset.filename;
    if (target.classList.contains('download-button')) {
      downloadFile(filename);
    } else if (target.classList.contains('view-button')) {
      viewFile(filename);
    } else if (target.classList.contains('delete-button')) {
      deleteFile(filename);
    } else if (target.classList.contains('temp-link-button')) {
      openTempLinkModal(filename);
    }
  });
}

// Temporary link modal functions
function openTempLinkModal(filename) {
  if (!tempLinkModal || !tempLinkFilename || !tempLinkResult) {
    console.error('Temp link modal elements not found');
    return;
  }
  
  currentTempLinkFilename = filename;
  tempLinkFilename.textContent = filename;
  tempLinkResult.classList.add('is-hidden');
  tempLinkModal.classList.add('is-active');
}

function handleCloseTempLinkModal() {
  if (tempLinkModal) tempLinkModal.classList.remove('is-active');
  currentTempLinkFilename = '';
}

async function generateTemporaryLink() {
  const token = localStorage.getItem('jwtToken');
  
  // Get folder ID from URL params
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId) {
    showNotification('Folder ID not found', 'is-danger');
    return;
  }
  
  if (!tempLinkDuration || !tempLinkResult || !tempLinkUrl) {
    console.error('Temp link elements not found');
    return;
  }
  
  const hours = parseInt(tempLinkDuration.value);
  
  try {
    const response = await fetch('/api/make-a-temporary-download-link', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        folderId,
        filename: currentTempLinkFilename,
        hours
      })
    });
    
    if (!response.ok) {
      throw new Error('Failed to generate temporary link');
    }
    
    const data = await response.json();
    tempLinkUrl.value = data.url;
    tempLinkResult.classList.remove('is-hidden');
  } catch (error) {
    console.error('Error generating temporary link:', error);
    showNotification('Failed to generate temporary link', 'is-danger');
  }
}

function copyTempLink() {
  if (!tempLinkUrl) {
    console.error('Temp link URL element not found');
    return;
  }
  
  // Use modern Clipboard API
  if (navigator.clipboard) {
    navigator.clipboard.writeText(tempLinkUrl.value)
      .then(() => {
        showNotification('Link copied to clipboard', 'is-success');
      })
      .catch(err => {
        console.error('Could not copy text: ', err);
        // Fallback to old method
        tempLinkUrl.select();
        document.execCommand('copy');
        showNotification('Link copied to clipboard', 'is-success');
      });
  } else {
    // Fallback for browsers without Clipboard API
    tempLinkUrl.select();
    document.execCommand('copy');
    showNotification('Link copied to clipboard', 'is-success');
  }
}

// Add event listeners for temp link modal
if (generateTempLinkButton) {
  generateTempLinkButton.addEventListener('click', generateTemporaryLink);
}

if (copyTempLinkButton) {
  copyTempLinkButton.addEventListener('click', copyTempLink);
}

if (closeTempLinkModal) {
  closeTempLinkModal.addEventListener('click', handleCloseTempLinkModal);
}

if (closeTempLinkModalFooter) {
  closeTempLinkModalFooter.addEventListener('click', handleCloseTempLinkModal);
}

// Update public button text based on folder's public status
async function updatePublicButtonText() {
  // Get folder ID from URL params instead of relying on DOM element
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId || !makePublicButton) {
    return;
  }
  
  try {
    const response = await fetch(`/api/is-folder-public/${folderId}`);
    const data = await response.json();
    
    if (data.isPublic) {
      makePublicButton.innerHTML = `
        <span class="icon"><i class="fas fa-lock"></i></span>
        <span>Make Private</span>
      `;
      makePublicButton.classList.remove('is-success');
      makePublicButton.classList.add('is-warning');
      makePublicButton.onclick = makePrivate;
    } else {
      makePublicButton.innerHTML = `
        <span class="icon"><i class="fas fa-globe"></i></span>
        <span>Make Public</span>
      `;
      makePublicButton.classList.remove('is-warning');
      makePublicButton.classList.add('is-success');
      makePublicButton.onclick = makePublic;
    }
  } catch (error) {
    console.error('Error checking folder public status:', error);
  }
}

// Make folder private
async function makePrivate() {
  const token = localStorage.getItem('jwtToken');
  
  // Get folder ID from URL params
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId) {
    showNotification('Folder ID not found', 'is-danger');
    return;
  }
  
  try {
    const response = await fetch(`/api/make-my-folder-private/${folderId}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Failed to make folder private');
    }
    
    showNotification('Folder is now private', 'is-success');
    updatePublicButtonText();
  } catch (error) {
    console.error('Error making folder private:', error);
    showNotification('Failed to make folder private', 'is-danger');
  }
}

// Add this new function for exporting folder as ZIP
function exportAsZip() {
  const urlParams = new URLSearchParams(window.location.search);
  const folderId = urlParams.get('folderID');
  
  if (!folderId) {
    showNotification('Folder ID not found', 'is-danger');
    return;
  }
  
  const token = localStorage.getItem('jwtToken');
  if (!token) {
    showNotification('You must be logged in to export', 'is-danger');
    return;
  }
  
  // Show loading notification
  showNotification('Preparing ZIP file for download...', 'is-info');
  
  // Create a download link
  const downloadLink = document.createElement('a');
  downloadLink.href = `/api/export-as-zip/${folderId}`;
  downloadLink.setAttribute('download', '');
  
  // Add the authorization header
  fetch(`/api/export-as-zip/${folderId}`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  })
  .then(response => {
    if (!response.ok) {
      throw new Error(`Error ${response.status}: ${response.statusText}`);
    }
    return response.blob();
  })
  .then(blob => {
    const url = window.URL.createObjectURL(blob);
    downloadLink.href = url;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);
    window.URL.revokeObjectURL(url);
    showNotification('ZIP download started successfully', 'is-success');
  })
  .catch(error => {
    console.error('Export error:', error);
    showNotification(`Failed to export folder: ${error.message}`, 'is-danger');
  });
}
