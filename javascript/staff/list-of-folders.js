    // Global variables
    let allFolders = [];
    let currentSort = { field: 'id', direction: 'asc' };
    
    // DOM elements
    const folderListContainer = document.getElementById('folderListContainer');
    const searchInput = document.getElementById('searchInput');
    const refreshBtn = document.getElementById('refreshBtn');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const totalFoldersElem = document.getElementById('totalFolders');
    const uniqueOwnersElem = document.getElementById('uniqueOwners');
    const unassignedFoldersElem = document.getElementById('unassignedFolders');
    
    // Event listeners
    document.addEventListener('DOMContentLoaded', fetchFolders);
    refreshBtn.addEventListener('click', fetchFolders);
    searchInput.addEventListener('input', filterFolders);
    
    document.querySelectorAll('.sort-option').forEach(option => {
      option.addEventListener('click', (e) => {
        e.preventDefault();
        const sortField = e.target.dataset.sort;
        if (currentSort.field === sortField) {
          currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
        } else {
          currentSort.field = sortField;
          currentSort.direction = 'asc';
        }
        renderFolders(allFolders);
      });
    });

    // Fetch folders data
    async function fetchFolders() {
      showLoading(true);
      
      try {
        const token = localStorage.getItem('jwtToken');
        if (!token) {
          showError('Authentication token not found. Please log in.');
          return;
        }
        
        const response = await fetch('/api/staff/get-for-all-folders-ID', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          }
        });

        if (!response.ok) {
          throw new Error(`Error ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        allFolders = data.folders || [];
        
        updateStats(allFolders);
        renderFolders(allFolders);
      } catch (error) {
        console.error('Error fetching folders:', error);
        showError('Failed to load folder data. Please try again or contact support.');
      } finally {
        showLoading(false);
      }
    }
    
    // Render folders to DOM
    function renderFolders(folders) {
      if (folders.length === 0) {
        folderListContainer.innerHTML = `
          <div class="no-folders">
            <i class="fas fa-folder-open fa-3x mb-3"></i>
            <h4>No folders found</h4>
            <p>There are no folders to display or your search returned no results.</p>
          </div>
        `;
        return;
      }
      
      // Sort folders
      const sortedFolders = sortFolders(folders, currentSort.field, currentSort.direction);
      
      // Create folder grid
      folderListContainer.innerHTML = `
        <div class="row p-3">
          ${sortedFolders.map(folder => createFolderCard(folder)).join('')}
        </div>
      `;
      
      // Add event listeners to folder cards
      document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const folderId = e.currentTarget.dataset.id;
          copyToClipboard(folderId);
          
          // Show copied feedback
          const originalHtml = e.currentTarget.innerHTML;
          e.currentTarget.innerHTML = '<i class="fas fa-check"></i> Copied!';
          e.currentTarget.classList.remove('btn-outline-secondary');
          e.currentTarget.classList.add('btn-success');
          
          setTimeout(() => {
            e.currentTarget.innerHTML = originalHtml;
            e.currentTarget.classList.remove('btn-success');
            e.currentTarget.classList.add('btn-outline-secondary');
          }, 2000);
        });
      });
    }
    
    // Create HTML for a single folder card
    function createFolderCard(folder) {
      const ownerDisplay = folder.owner 
        ? `<span class="badge bg-secondary badge-owner"><i class="fas fa-user me-1"></i>${folder.owner}</span>`
        : `<span class="badge bg-warning text-dark"><i class="fas fa-exclamation-triangle me-1"></i>Unassigned</span>`;
      
      return `
        <div class="col-md-6 col-lg-4 mb-3">
          <div class="card folder-card h-100">
            <div class="card-body">
              <div class="d-flex align-items-center mb-3">
                <div class="me-3">
                  <i class="fas fa-folder folder-icon"></i>
                </div>
                <div>
                  <h5 class="card-title mb-1 text-truncate" title="${folder.folderId}">
                    ${folder.folderId}
                  </h5>
                  <div>${ownerDisplay}</div>
                </div>
              </div>
              <button class="btn btn-outline-secondary btn-sm copy-btn w-100" data-id="${folder.folderId}">
                <i class="fas fa-copy me-1"></i> Copy ID
              </button>
            </div>
          </div>
        </div>
      `;
    }
    
    // Filter folders based on search input
    function filterFolders() {
      const searchTerm = searchInput.value.toLowerCase().trim();
      
      if (!searchTerm) {
        renderFolders(allFolders);
        return;
      }
      
      const filteredFolders = allFolders.filter(folder => {
        const folderId = (folder.folderId || '').toLowerCase();
        const ownerName = (folder.owner || '').toLowerCase();
        
        return folderId.includes(searchTerm) || ownerName.includes(searchTerm);
      });
      
      renderFolders(filteredFolders);
    }
    
    // Sort folders
    function sortFolders(folders, field, direction) {
      return [...folders].sort((a, b) => {
        let valueA, valueB;
        
        if (field === 'id') {
          valueA = a.folderId || '';
          valueB = b.folderId || '';
        } else if (field === 'owner') {
          valueA = a.owner || '';
          valueB = b.owner || '';
        }
        
        // Handle string comparison
        if (typeof valueA === 'string') {
          if (direction === 'asc') {
            return valueA.localeCompare(valueB);
          } else {
            return valueB.localeCompare(valueA);
          }
        }
        
        // Fallback for non-string values
        if (direction === 'asc') {
          return valueA - valueB;
        } else {
          return valueB - valueA;
        }
      });
    }
    
    // Update statistics
    function updateStats(folders) {
      const totalCount = folders.length;
      
      // Count unique owners
      const uniqueOwners = new Set();
      let unassignedCount = 0;
      
      folders.forEach(folder => {
        if (folder.owner) {
          uniqueOwners.add(folder.owner);
        } else {
          unassignedCount++;
        }
      });
      
      // Update DOM
      totalFoldersElem.textContent = totalCount;
      uniqueOwnersElem.textContent = uniqueOwners.size;
      unassignedFoldersElem.textContent = unassignedCount;
    }
    
    // Copy text to clipboard
    function copyToClipboard(text) {
      navigator.clipboard.writeText(text)
        .catch(err => {
          console.error('Could not copy text: ', err);
          // Fallback method
          const textArea = document.createElement('textarea');
          textArea.value = text;
          document.body.appendChild(textArea);
          textArea.select();
          document.execCommand('copy');
          document.body.removeChild(textArea);
        });
    }
    
    // Show/hide loading indicator
    function showLoading(isLoading) {
      loadingIndicator.style.display = isLoading ? 'flex' : 'none';
    }
    
    // Show error message
    function showError(message) {
      folderListContainer.innerHTML = `
        <div class="error-container">
          <div class="d-flex align-items-center">
            <i class="fas fa-exclamation-circle text-danger fa-2x me-3"></i>
            <div>
              <h5 class="text-danger mb-1">Error</h5>
              <p class="mb-0">${message}</p>
            </div>
          </div>
        </div>
      `;
    }