(async function(){
    // Get token from storage or prompt
    const token = localStorage.getItem('jwtToken') || prompt('Enter JWT token');
    
    // Store token in localStorage for future use
    if (token) {
      localStorage.setItem('jwtToken', token);
    }
    
    // Logout button
    document.getElementById('logout-button').addEventListener('click', () => {
      localStorage.removeItem('jwtToken');
      alert('Logged out successfully');
      location.reload();
    });
    
    // Toggle between visual and JSON views
    document.getElementById('tab-view').addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('tab-view').parentElement.classList.add('is-active');
      document.getElementById('tab-json').parentElement.classList.remove('is-active');
      document.getElementById('visual-view').style.display = 'block';
      document.getElementById('json-view').style.display = 'none';
    });
    
    document.getElementById('tab-json').addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('tab-json').parentElement.classList.add('is-active');
      document.getElementById('tab-view').parentElement.classList.remove('is-active');
      document.getElementById('visual-view').style.display = 'none';
      document.getElementById('json-view').style.display = 'block';
    });
    
    // Close error message
    document.getElementById('close-error').addEventListener('click', () => {
      document.getElementById('error-container').style.display = 'none';
    });
    
    // Form submission
    document.getElementById('form').onsubmit = async e => {
      e.preventDefault();
      const folderId = document.getElementById('folderId').value.trim();
      
      if (!folderId) {
        showError('Please enter a folder ID');
        return;
      }
      
      // Show loading indicator and hide results
      document.getElementById('loading').style.display = 'block';
      document.getElementById('results-container').style.display = 'none';
      document.getElementById('error-container').style.display = 'none';
      
      try {
        const res = await fetch(`/api/staff/folder-contents?folderId=${folderId}`, {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        
        if (!res.ok) {
          throw new Error(await res.text() || `Error: ${res.status} ${res.statusText}`);
        }
        
        const data = await res.json();
        
        // Hide loading indicator
        document.getElementById('loading').style.display = 'none';
        
        // Show results
        document.getElementById('results-container').style.display = 'block';
        document.getElementById('current-folder-id').textContent = folderId;
        
        // Parse and display files
        renderFileList(data);
        
        // Display raw JSON
        document.getElementById('output').textContent = JSON.stringify(data, null, 2);
        
        // Update file count
        const fileCount = data.filter(item => item && item.filename).length;
        document.getElementById('file-count').textContent = `${fileCount} files`;
        
      } catch (err) {
        document.getElementById('loading').style.display = 'none';
        showError('Error: ' + err.message);
      }
    };
    
    // Show error message
    function showError(message) {
      const errorContainer = document.getElementById('error-container');
      const errorMessage = document.getElementById('error-message');
      
      errorMessage.textContent = message;
      errorContainer.style.display = 'block';
    }
    
    // Render file list
    function renderFileList(files) {
      const fileList = document.getElementById('file-list');
      fileList.innerHTML = '';
      
      // Create table
      const table = document.createElement('table');
      table.className = 'table is-fullwidth is-hoverable';
      
      // Create table header
      const thead = document.createElement('thead');
      thead.innerHTML = `
        <tr>
          <th>File Name</th>
          <th>Size</th>
          <th>Last Modified</th>
          <th>Type</th>
        </tr>
      `;
      table.appendChild(thead);
      
      // Create table body
      const tbody = document.createElement('tbody');
      
      // Add files to table
      files.forEach(file => {
        if (file && file.filename) {
          const row = document.createElement('tr');
          row.className = 'file-item';
          
          // Get file extension
          const fileExtension = file.type || (file.filename.includes('.') ? 
            file.filename.split('.').pop().toLowerCase() : '');
          
          // Determine icon
          let icon = 'fas fa-file';
          if (fileExtension === '.pdf' || fileExtension === 'pdf') {
            icon = 'fas fa-file-pdf';
          } else if (fileExtension === '.mp3' || fileExtension === 'mp3') {
            icon = 'fas fa-file-audio';
          } else if (fileExtension === '.mp4' || fileExtension === 'mp4') {
            icon = 'fas fa-file-video';
          } else if (fileExtension === '.txt' || fileExtension === 'txt') {
            icon = 'fas fa-file-alt';
          } else if (fileExtension === '.jpg' || fileExtension === '.png' || 
                     fileExtension === 'jpg' || fileExtension === 'png') {
            icon = 'fas fa-file-image';
          }
          
          // Format file size
          const size = formatFileSize(file.size);
          
          // Format date
          const date = file.lastModified ? new Date(file.lastModified).toLocaleString() : 'Unknown';
          
          row.innerHTML = `
            <td>
              <span class="icon-text">
                <span class="icon file-icon">
                  <i class="${icon}"></i>
                </span>
                <span>${file.filename}</span>
              </span>
            </td>
            <td class="file-size">${size}</td>
            <td class="file-date">${date}</td>
            <td>${fileExtension || 'Unknown'}</td>
          `;
          
          tbody.appendChild(row);
        }
      });
      
      table.appendChild(tbody);
      fileList.appendChild(table);
    }
    
    // Format file size
    function formatFileSize(bytes) {
      if (!bytes) return 'Unknown';
      
      const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
      if (bytes === 0) return '0 Byte';
      const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
      return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
    }
  })();