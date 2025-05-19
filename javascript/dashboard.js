document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }

    // Verify token with server
    fetch('/api/verify-token', {
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
      const response = await fetch('/api/recommended-files', {
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
      const response = await fetch('/api/shared-folders', {
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
      const response = await fetch('/api/create-folder', {
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
      const response = await fetch('/api/my-folders', {
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
      const response = await fetch('/api/change-your-password', {
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
      const response = await fetch('/api/check-role', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.role === 'staff' || data.role === 'owner') {
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
  
  // MFA related functions
  
  // Show the MFA setup modal
  function showSetupMFAModal() {
    // Reset any previous content
    document.getElementById('mfaStep1').style.display = 'block';
    document.getElementById('mfaStep2').style.display = 'none';
    document.getElementById('mfaSuccess').style.display = 'none';
    document.getElementById('mfaTokenInput').value = '';
    document.getElementById('mfaTokenError').style.display = 'none';
    
    // Show the modal
    document.getElementById('setupMFAModal').style.display = 'flex';
    
    // Fetch MFA setup data from the server
    fetchMFASetupData();
  }
  
  // Hide the MFA setup modal
  function hideMFAModal() {
    document.getElementById('setupMFAModal').style.display = 'none';
  }
  
  // Fetch MFA setup data from the server
  async function fetchMFASetupData() {
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }
    
    try {
      const response = await fetch('/api/setup-mfa', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({})      
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        if (errorData.message === 'MFA already enabled') {
          alert('MFA is already enabled for your account.');
          hideMFAModal();
        } else {
          throw new Error(errorData.message || 'Error setting up MFA');
        }
        return;
      }
      
      const data = await response.json();
      
      // Display the QR code image
      document.getElementById('qrCodeImage').src = data.qrCode;
      
      // Extract and display the secret key
      const secretMatch = data.otpauth_url.match(/secret=([A-Z0-9]+)/);
      if (secretMatch && secretMatch[1]) {
        document.getElementById('secretKey').textContent = secretMatch[1];
      }
      
    } catch (error) {
      console.error('Error fetching MFA setup data:', error);
      alert('Error setting up MFA: ' + (error.message || 'Unknown error'));
      hideMFAModal();
    }
  }
  
  // Show the MFA verification step
  function showMFAVerificationStep() {
    document.getElementById('mfaStep1').style.display = 'none';
    document.getElementById('mfaStep2').style.display = 'block';
    document.getElementById('mfaSuccess').style.display = 'none';
    document.getElementById('mfaTokenInput').focus();
  }
  
  // Go back to the first step of MFA setup
  function backToMFAStep1() {
    document.getElementById('mfaStep1').style.display = 'block';
    document.getElementById('mfaStep2').style.display = 'none';
    document.getElementById('mfaSuccess').style.display = 'none';
  }
  
  // Verify the MFA token
  async function verifyMFAToken() {
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }
    
    const mfaToken = document.getElementById('mfaTokenInput').value.trim();
    
    // Validate the token
    if (!mfaToken || mfaToken.length !== 6 || !/^\d+$/.test(mfaToken)) {
      document.getElementById('mfaTokenError').textContent = 'Please enter a valid 6-digit code';
      document.getElementById('mfaTokenError').style.display = 'block';
      return;
    }
    
    try {
      const response = await fetch('/api/verify-mfa', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ token: mfaToken })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        document.getElementById('mfaTokenError').textContent = errorData.error || 'Invalid verification code';
        document.getElementById('mfaTokenError').style.display = 'block';
        return;
      }
      
      // Show success message
      document.getElementById('mfaStep1').style.display = 'none';
      document.getElementById('mfaStep2').style.display = 'none';
      document.getElementById('mfaSuccess').style.display = 'block';
      
    } catch (error) {
      console.error('Error verifying MFA token:', error);
      document.getElementById('mfaTokenError').textContent = 'Error verifying code: ' + (error.message || 'Unknown error');
      document.getElementById('mfaTokenError').style.display = 'block';
    }
  }

  // Show group creation modal
  function showMakeGroupModal() {
    // Reset form elements
    document.getElementById('groupFolderSelect').innerHTML = '<option value="">-- Select a folder --</option>';
    document.getElementById('groupNameInput').value = '';
    document.getElementById('groupEmailsInput').value = '';
    document.getElementById('folderSelectError').style.display = 'none';
    document.getElementById('groupNameError').style.display = 'none';
    document.getElementById('groupEmailsError').style.display = 'none';
    document.getElementById('generalGroupError').style.display = 'none';
    
    // Show first step, hide success screen
    document.getElementById('groupStep1').style.display = 'block';
    document.getElementById('groupSuccess').style.display = 'none';
    
    // Load user's folders for selection
    loadFoldersForGroupCreation();
    
    // Display the modal
    document.getElementById('makeGroupModal').style.display = 'flex';
  }
  
  // Hide the group creation modal
  function hideMakeGroupModal() {
    document.getElementById('makeGroupModal').style.display = 'none';
  }
  
  // Load user's folders for the group creation dropdown
  async function loadFoldersForGroupCreation() {
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }
    
    try {
      const response = await fetch('/api/my-folders', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to load folders');
      }
      
      const folders = await response.json();
      const select = document.getElementById('groupFolderSelect');
      
      if (folders.length === 0) {
        select.innerHTML = '<option value="">No folders available</option>';
        return;
      }
      
      const options = folders.map(folder => 
        `<option value="${folder.folderId}">${folder.folderName}</option>`
      );
      
      select.innerHTML = '<option value="">-- Select a folder --</option>' + options.join('');
    } catch (error) {
      console.error('Error loading folders:', error);
      document.getElementById('generalGroupError').textContent = 'Error loading folders. Please try again later.';
      document.getElementById('generalGroupError').style.display = 'block';
    }
  }
  
  // Create a new group
  async function createGroup() {
    // Reset error messages
    document.getElementById('folderSelectError').style.display = 'none';
    document.getElementById('groupNameError').style.display = 'none';
    document.getElementById('groupEmailsError').style.display = 'none';
    document.getElementById('generalGroupError').style.display = 'none';
    
    // Get form values
    const folderId = document.getElementById('groupFolderSelect').value;
    const groupName = document.getElementById('groupNameInput').value.trim();
    const emailsText = document.getElementById('groupEmailsInput').value.trim();
    
    // Validate inputs
    let hasError = false;
    
    if (!folderId) {
      document.getElementById('folderSelectError').textContent = 'Please select a folder';
      document.getElementById('folderSelectError').style.display = 'block';
      hasError = true;
    }
    
    if (!groupName) {
      document.getElementById('groupNameError').textContent = 'Please enter a group name';
      document.getElementById('groupNameError').style.display = 'block';
      hasError = true;
    } else if (!/^[\w\- ]{3,50}$/.test(groupName)) {
      document.getElementById('groupNameError').textContent = 'Group name should be 3-50 characters and contain only letters, numbers, spaces, and dashes';
      document.getElementById('groupNameError').style.display = 'block';
      hasError = true;
    }
    
    // Process email addresses (split by newlines and clean)
    const userEmails = emailsText
      .split('\n')
      .map(email => email.trim())
      .filter(email => email.length > 0);
    
    if (userEmails.length < 2) {
      document.getElementById('groupEmailsError').textContent = 'Please enter at least 2 email addresses';
      document.getElementById('groupEmailsError').style.display = 'block';
      hasError = true;
    }
    
    // Check if emails are valid format
    const invalidEmails = userEmails.filter(email => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email));
    if (invalidEmails.length > 0) {
      document.getElementById('groupEmailsError').textContent = `Invalid email format: ${invalidEmails.join(', ')}`;
      document.getElementById('groupEmailsError').style.display = 'block';
      hasError = true;
    }
    
    if (hasError) return;
    
    // Submit to server
    const token = localStorage.getItem('jwtToken');
    if (!token) {
      window.location.href = '/index.html';
      return;
    }
    
    try {
      const response = await fetch('/api/folders/make-a-group', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          folderId,
          groupName,
          userEmails
        })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        document.getElementById('generalGroupError').textContent = data.error || 'Failed to create group';
        document.getElementById('generalGroupError').style.display = 'block';
        return;
      }
      
      // Show success screen
      document.getElementById('groupStep1').style.display = 'none';
      document.getElementById('groupSuccess').style.display = 'block';
      
      // Set success message
      let successMessage = `Group "${groupName}" created successfully!`;
      if (data.notFoundUsers && data.notFoundUsers.length > 0) {
        successMessage += ` Note: ${data.notFoundUsers.length} email(s) could not be found in the system.`;
      }
      document.getElementById('groupSuccessMessage').textContent = successMessage;
      
      // Log success in console
      console.log('Group created:', data);
    } catch (error) {
      console.error('Error creating group:', error);
      document.getElementById('generalGroupError').textContent = 'An error occurred while creating the group';
      document.getElementById('generalGroupError').style.display = 'block';
    }
  }

  // API Key Management Functions
  async function showApiKeys() {
    // Update active state
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    document.querySelector('.nav-item:nth-child(3)').classList.add('active');
    
    // Hide other sections and show API keys section
    document.querySelectorAll('.content-section').forEach(section => section.style.display = 'none');
    document.getElementById('apiKeysSection').style.display = 'block';
    
    // Update page title
    document.querySelector('.page-title').textContent = 'API Keys';
    
    // Load API keys
    await loadApiKeys();
  }

  async function loadApiKeys() {
    try {
      const token = localStorage.getItem('jwtToken');
      if (!token) {
        window.location.href = '/index.html';
        return;
      }

      const response = await fetch('/api/v1/keys', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem('jwtToken');
          window.location.href = '/index.html';
          return;
        }
        throw new Error('Failed to load API keys');
      }
      
      const data = await response.json();
      const keysList = document.getElementById('apiKeysList');
      keysList.innerHTML = '';
      
      if (data.keys.length === 0) {
        keysList.innerHTML = `
          <div class="empty-state">
            <i class="fas fa-key"></i>
            <h3>No API Keys</h3>
            <p>Generate your first API key to get started with the API</p>
          </div>
        `;
        return;
      }
      
      data.keys.forEach(key => {
        const keyElement = document.createElement('div');
        keyElement.className = 'api-key-item';
        keyElement.innerHTML = `
          <div class="api-key-header">
            <div class="api-key-description">${key.description}</div>
            <div class="api-key-created">Created: ${new Date(key.created).toLocaleDateString()}</div>
          </div>
          <div class="api-key-stats">
            <div>Last used: ${key.lastUsed ? new Date(key.lastUsed).toLocaleString() : 'Never'}</div>
            <div>Total requests: ${key.usageCount || 0}</div>
          </div>
          <button class="delete-key-btn" onclick="revokeApiKey('${key._id}')">
            <i class="fas fa-trash"></i> Revoke
          </button>
        `;
        keysList.appendChild(keyElement);
      });
    } catch (error) {
      console.error('Error loading API keys:', error);
      showNotification('Failed to load API keys', 'error');
    }
  }

  function showApiKeyModal() {
    document.getElementById('generateApiKeyModal').style.display = 'flex';
    document.getElementById('apiKeyStep1').style.display = 'block';
    document.getElementById('apiKeyStep2').style.display = 'none';
    document.getElementById('apiKeyDescription').value = '';
    document.getElementById('apiKeyError').style.display = 'none';
  }

  function hideApiKeyModal() {
    document.getElementById('generateApiKeyModal').style.display = 'none';
    loadApiKeys(); // Refresh the keys list
  }

  async function submitApiKeyGeneration() {
    const description = document.getElementById('apiKeyDescription').value.trim();
    const errorElement = document.getElementById('apiKeyError');
    
    if (!description) {
      errorElement.textContent = 'Please enter a description for your API key';
      errorElement.style.display = 'block';
      return;
    }

    try {
      const token = localStorage.getItem('jwtToken');
      if (!token) {
        window.location.href = '/index.html';
        return;
      }

      const response = await fetch('/api/v1/keys', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ description })
      });
      
      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem('jwtToken');
          window.location.href = '/index.html';
          return;
        }
        throw new Error('Failed to generate API key');
      }
      
      const data = await response.json();
      
      // Show the new key
      document.getElementById('apiKeyStep1').style.display = 'none';
      document.getElementById('apiKeyStep2').style.display = 'block';
      document.getElementById('newApiKeyValue').textContent = data.key;
      
      showNotification('API key generated successfully', 'success');
    } catch (error) {
      console.error('Error generating API key:', error);
      errorElement.textContent = 'Failed to generate API key. Please try again.';
      errorElement.style.display = 'block';
    }
  }

  function copyNewApiKey() {
    const keyElement = document.getElementById('newApiKeyValue');
    navigator.clipboard.writeText(keyElement.textContent)
      .then(() => {
        showNotification('API key copied to clipboard!', 'success');
      })
      .catch(err => {
        console.error('Failed to copy:', err);
        showNotification('Failed to copy API key', 'error');
      });
  }

  async function revokeApiKey(keyId) {
    if (!confirm('Are you sure you want to revoke this API key? This action cannot be undone.')) {
      return;
    }
    
    try {
      const token = localStorage.getItem('jwtToken');
      if (!token) {
        window.location.href = '/index.html';
        return;
      }

      const response = await fetch(`/api/v1/keys/${keyId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem('jwtToken');
          window.location.href = '/index.html';
          return;
        }
        throw new Error('Failed to revoke API key');
      }
      
      showNotification('API key revoked successfully', 'success');
      await loadApiKeys();
    } catch (error) {
      console.error('Error revoking API key:', error);
      showNotification('Failed to revoke API key', 'error');
    }
  }