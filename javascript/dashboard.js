document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }

    // Verify token with server
    fetch('http://localhost:3000/api/verify-token', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => {
      if (!response.ok) {
        localStorage.removeItem('jwtToken');
        window.location.href = '/index.html';
      } else {
        // Check if user is staff member
        checkUserRole();
      }
    })
    .catch(() => {
      localStorage.removeItem('jwtToken');
      window.location.href = '/index.html';
    });
    
    // Initialize the display
    showMyDrive();
    
    // Add click handler for home nav item
    document.getElementById('homeNav').addEventListener('click', activateHome);
  });
  
  // Activate My Drive section
  function activateMyDrive() {
    // Update navigation styling
    document.getElementById('myDriveNav').classList.add('active');
    document.getElementById('myDriveNav').classList.remove('shared-active');
    document.getElementById('sharedNav').classList.remove('shared-active');
    document.getElementById('sharedNav').classList.remove('active');
    document.getElementById('homeNav').classList.remove('active');
    document.getElementById('homeNav').classList.remove('shared-active');
    
    // Update page title
    document.querySelector('.page-title').textContent = 'My Folders';
    
    // Hide search bar
    document.querySelector('.search-bar').style.display = 'none';
    
    // Show My Drive content
    showMyDrive();
  }
  
  // Activate Shared with me section
  function activateShared() {
    // Update navigation styling
    document.getElementById('sharedNav').classList.add('shared-active');
    document.getElementById('myDriveNav').classList.remove('active');
    document.getElementById('myDriveNav').classList.remove('shared-active');
    document.getElementById('homeNav').classList.remove('active');
    document.getElementById('homeNav').classList.remove('shared-active');
    
    // Update page title
    document.querySelector('.page-title').textContent = 'Shared with me';
    
    // Hide search bar
    document.querySelector('.search-bar').style.display = 'none';
    
    // Show Shared with me content
    showSharedWithMe();
  }

  // Activate Home section
  function activateHome() {
    // Update navigation styling
    document.getElementById('homeNav').classList.add('active');
    document.getElementById('myDriveNav').classList.remove('active');
    document.getElementById('myDriveNav').classList.remove('shared-active');
    document.getElementById('sharedNav').classList.remove('shared-active');
    document.getElementById('sharedNav').classList.remove('active');
    
    // Update page title
    document.querySelector('.page-title').textContent = 'Home';
    
    // Show search bar
    document.querySelector('.search-bar').style.display = 'block';
    
    // Show Home content
    showHome();
  }
  
  // Show Home content with recommended files
  async function showHome() {
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }
    
    // Update page title
    document.querySelector('.page-title').textContent = 'Home';
    
    try {
      const response = await fetch('http://localhost:3000/api/recommended-files', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch recommended files');
      }
      
      const data = await response.json();
      const recommendedFiles = data.recommended || [];
      
      const folderGrid = document.getElementById('folderGrid');
      
      if (recommendedFiles.length === 0) {
        folderGrid.innerHTML = `
          <div class="empty-state">
            <i class="fas fa-file-alt fa-3x"></i>
            <h3>No Recent Files</h3>
            <p>Your recently accessed files will appear here</p>
          </div>
        `;
        return;
      }
      
      // Create HTML for the recommended files
      const filesHTML = recommendedFiles.map(file => {
        const fileExtension = file.filename.split('.').pop().toLowerCase();
        let iconClass = 'fa-file';
        let categoryClass = '';
        
        // Determine file icon based on extension
        if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'].includes(fileExtension)) {
          iconClass = 'fa-file-image';
          categoryClass = 'image';
        } else if (['pdf'].includes(fileExtension)) {
          iconClass = 'fa-file-pdf';
          categoryClass = 'pdf';
        } else if (['doc', 'docx', 'txt', 'rtf'].includes(fileExtension)) {
          iconClass = 'fa-file-word';
          categoryClass = 'document';
        } else if (['xls', 'xlsx', 'csv'].includes(fileExtension)) {
          iconClass = 'fa-file-excel';
          categoryClass = 'spreadsheet';
        } else if (['ppt', 'pptx'].includes(fileExtension)) {
          iconClass = 'fa-file-powerpoint';
          categoryClass = 'presentation';
        } else if (['mp3', 'wav', 'ogg', 'flac'].includes(fileExtension)) {
          iconClass = 'fa-file-audio';
          categoryClass = 'audio';
        } else if (['mp4', 'mov', 'avi', 'mkv', 'webm'].includes(fileExtension)) {
          iconClass = 'fa-file-video';
          categoryClass = 'video';
        } else if (['zip', 'rar', '7z', 'tar', 'gz'].includes(fileExtension)) {
          iconClass = 'fa-file-archive';
          categoryClass = 'archive';
        } else if (['js', 'html', 'css', 'py', 'java', 'php', 'c', 'cpp', 'h', 'json', 'xml'].includes(fileExtension)) {
          iconClass = 'fa-file-code';
          categoryClass = 'code';
        }
        
        const fileSize = formatFileSize(file.size);
        const lastModified = new Date(file.lastModified).toLocaleString();
        
        return `
          <div class="file-item" onclick="openFileFromHome('${file.folderId}', '${encodeURIComponent(file.filename)}')">
            <div class="file-icon ${categoryClass}">
              <i class="fas ${iconClass}"></i>
            </div>
            <div class="file-details">
              <div class="file-name">${file.filename}</div>
              <div class="file-info">
                <div class="file-size"><i class="fas fa-hdd"></i> ${fileSize}</div>
                <div class="dot-separator"><i class="fas fa-circle"></i></div>
                <div class="file-date"><i class="fas fa-clock"></i> ${lastModified}</div>
              </div>
            </div>
          </div>
        `;
      }).join('');
      
      folderGrid.innerHTML = `
        <div class="recommended-section">
          <div class="section-title">
            <i class="fas fa-clock"></i>
            Recently Modified Files
          </div>
          <div class="files-container">
            ${filesHTML}
          </div>
        </div>
      `;
    } catch (error) {
      console.error('Error loading recommended files:', error);
      document.getElementById('folderGrid').innerHTML = `
        <div class="notification is-danger">
          Error loading recommended files. Please try again later.
        </div>
      `;
    }
  }
  
  // Format file size
  function formatFileSize(bytes) {
    if (!bytes) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
  
  // Open file from home page - changed to open the associated folder instead of media viewer
  function openFileFromHome(folderId, filename) {
    // Redirect to the folder view instead of the media viewer
    window.location.href = `folder.html?folderID=${folderId}`;
  }

  function logout() {
    localStorage.removeItem('jwtToken');
    window.location.href = '/index.html';
  }

  function findFolder() {
    const searchInput = document.getElementById('searchInput').value.trim().toLowerCase();
    const folderItems = document.querySelectorAll('.folder-item');
    folderItems.forEach(item => {
      const folderName = item.querySelector('.folder-name').textContent.toLowerCase();
      if (folderName.includes(searchInput)) {
        item.style.display = 'block';
      } else {
        item.style.display = 'none';
      }
    });
  }

  // Show Shared with me content
  async function showSharedWithMe() {
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }

    try {
      const response = await fetch('http://localhost:3000/api/shared-folders', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      const folders = await response.json();

      const folderGrid = document.getElementById('folderGrid');
      folderGrid.innerHTML = folders.map(folder => `
        <div class="folder-item" onclick="openFolder('${folder.folderId}')">
          <div class="folder-icon shared"><i class="fas fa-folder-open"></i></div>
          <div class="folder-name">${folder.folderName.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
        </div>
      `).join('');
    } catch (error) {
      console.error('Error loading shared folders:', error);
    }
  }

  // Show create folder modal
  function showCreateFolderModal() {
    document.getElementById('createFolderModal').style.display = 'flex';
    document.getElementById('folderNameInput').focus();
  }

  // Hide create folder modal
  function hideCreateFolderModal() {
    document.getElementById('createFolderModal').style.display = 'none';
    document.getElementById('folderNameInput').value = '';
  }

  // Create new folder
  async function createFolder() {
    const folderName = document.getElementById('folderNameInput').value.trim();
    if (!folderName) return;

    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }

    try {
      const response = await fetch('http://localhost:3000/api/create-folder', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ folderName })
      });

      const data = await response.json();
      if (response.ok) {
        hideCreateFolderModal();
        showMyDrive(); // Refresh the folder list
      } else {
        alert(data.message || 'Error creating folder');
      }
    } catch (error) {
      alert('Error creating folder');
      console.error(error);
    }
  }

  // Show My Drive content
  async function showMyDrive() {
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }

    try {
      const response = await fetch('http://localhost:3000/api/my-folders', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      const folders = await response.json();

      const folderGrid = document.getElementById('folderGrid');
      folderGrid.innerHTML = folders.map(folder => `
        <div class="folder-item" onclick="openFolder('${folder.folderId}')">
          <div class="folder-icon"><i class="fas fa-folder"></i></div>
          <div class="folder-name">${folder.folderName.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
        </div>
      `).join('');
    } catch (error) {
      console.error('Error loading folders:', error);
    }
  }

  // Open folder
  function openFolder(folderId) {
    window.location.href = `folder.html?folderID=${folderId}`;
  }
  
  // Show change password modal
  function showChangePasswordModal() {
    // Clear previous inputs and errors
    document.getElementById('oldPasswordInput').value = '';
    document.getElementById('newPasswordInput').value = '';
    document.getElementById('confirmPasswordInput').value = '';
    document.getElementById('newPasswordError').style.display = 'none';
    document.getElementById('confirmPasswordError').style.display = 'none';
    document.getElementById('generalPasswordError').style.display = 'none';
    
    document.getElementById('changePasswordModal').style.display = 'flex';
    document.getElementById('oldPasswordInput').focus();
  }
  
  // Hide change password modal
  function hideChangePasswordModal() {
    document.getElementById('changePasswordModal').style.display = 'none';
  }
  
  // Change password
  async function changePassword() {
    // Reset error messages
    document.getElementById('newPasswordError').style.display = 'none';
    document.getElementById('confirmPasswordError').style.display = 'none';
    document.getElementById('generalPasswordError').style.display = 'none';
    
    const oldPassword = document.getElementById('oldPasswordInput').value;
    const newPassword = document.getElementById('newPasswordInput').value;
    const confirmPassword = document.getElementById('confirmPasswordInput').value;
    
    // Validate inputs
    let hasError = false;
    
    if (!oldPassword) {
      document.getElementById('generalPasswordError').textContent = 'Please enter your current password';
      document.getElementById('generalPasswordError').style.display = 'block';
      hasError = true;
    }
    
    if (newPassword.length < 8) {
      document.getElementById('newPasswordError').textContent = 'Password must be at least 8 characters';
      document.getElementById('newPasswordError').style.display = 'block';
      hasError = true;
    }
    
    if (newPassword !== confirmPassword) {
      document.getElementById('confirmPasswordError').textContent = 'Passwords do not match';
      document.getElementById('confirmPasswordError').style.display = 'block';
      hasError = true;
    }
    
    if (hasError) return;
    
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }
    
    try {
      const response = await fetch('http://localhost:3000/api/change-your-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ oldPassword, newPassword })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        hideChangePasswordModal();
        alert('Password changed successfully');
      } else {
        document.getElementById('generalPasswordError').textContent = data.message || 'Error changing password';
        document.getElementById('generalPasswordError').style.display = 'block';
      }
    } catch (error) {
      document.getElementById('generalPasswordError').textContent = 'Error connecting to server';
      document.getElementById('generalPasswordError').style.display = 'block';
      console.error(error);
    }
  }

  // Check user role to show/hide staff button
  async function checkUserRole() {
    const token = localStorage.getItem('jwtToken');
    if (!token) return;
    
    try {
      const response = await fetch('http://localhost:3000/api/check-role', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.role === 'staff') {
          // Show staff button if user is a staff member
          document.getElementById('staffNav').style.display = 'flex';
        }
      }
    } catch (error) {
      console.error('Error checking user role:', error);
    }
  }
  
  // Navigate to staff dashboard
  function goToStaffDashboard() {
    window.location.href = '/staff/Hello.html';
  }