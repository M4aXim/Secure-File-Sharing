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
      }
    })
    .catch(() => {
      localStorage.removeItem('jwtToken');
      window.location.href = '/index.html';
    });
    
    // Initialize the display
    showMyDrive();
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
    
    // Show Shared with me content
    showSharedWithMe();
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