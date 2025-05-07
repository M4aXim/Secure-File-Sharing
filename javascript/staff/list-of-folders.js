    // Global variables
    let allFolders = [];
    let currentSort = { field: 'id', direction: 'asc' };
    
    // DOM elements
    const folderGrid = document.getElementById('folderGrid');
    const searchInput = document.getElementById('searchInput');
    const refreshBtn = document.getElementById('refreshBtn');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const totalFoldersElem = document.getElementById('totalFolders');
    const uniqueOwnersElem = document.getElementById('uniqueOwners');
    
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
        folderGrid.innerHTML = `
          <div class="col-12">
            <div class="no-folders">
              <i class="fas fa-folder-open fa-3x mb-3"></i>
              <h4>No folders found</h4>
              <p>There are no folders to display or your search returned no results.</p>
            </div>
          </div>
        `;
        return;
      }
      
      // Sort folders
      const sortedFolders = sortFolders(folders, currentSort.field, currentSort.direction);
      
      // Create folder grid
      folderGrid.innerHTML = sortedFolders.map(folder => createFolderCard(folder)).join('');
    }
    
    // Create HTML for a single folder card
    function createFolderCard(folder) {
      const ownerDisplay = folder.owner 
        ? `<span class="badge bg-secondary badge-owner"><i class="fas fa-user me-1"></i>${folder.owner}</span>`
        : `<span class="badge bg-warning text-dark"><i class="fas fa-exclamation-triangle me-1"></i>Unassigned</span>`;
      
      return `
        <div class="card folder-card" data-id="${folder.folderId}">
          <div class="card-body">
            <div class="d-flex align-items-center">
              <div class="me-3">
                <i class="fas fa-folder folder-icon"></i>
              </div>
              <div>
                <h5 class="card-title mb-1 text-truncate" title="${folder.folderId}">
                  ${folder.folderId}
                </h5>
                <div class="d-flex gap-2">
                  ${ownerDisplay}
                </div>
              </div>
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
        
        switch (field) {
          case 'id':
            valueA = a.folderId || '';
            valueB = b.folderId || '';
            break;
          case 'owner':
            valueA = a.owner || '';
            valueB = b.owner || '';
            break;
          default:
            valueA = a.folderId || '';
            valueB = b.folderId || '';
        }
        
        return direction === 'asc' 
          ? valueA.localeCompare(valueB)
          : valueB.localeCompare(valueA);
      });
    }
    
    // Update statistics
    function updateStats(folders) {
      const totalCount = folders.length;
      
      // Count unique owners
      const uniqueOwners = new Set();
      folders.forEach(folder => {
        if (folder.owner) {
          uniqueOwners.add(folder.owner);
        }
      });
      
      // Update DOM
      totalFoldersElem.textContent = totalCount;
      uniqueOwnersElem.textContent = uniqueOwners.size;
    }
    
    // Show/hide loading indicator
    function showLoading(isLoading) {
      loadingIndicator.style.display = isLoading ? 'block' : 'none';
    }
    
    // Show error message
    function showError(message) {
      folderGrid.innerHTML = `
        <div class="col-12">
          <div class="error-container">
            <div class="d-flex align-items-center">
              <i class="fas fa-exclamation-circle text-danger fa-2x me-3"></i>
              <div>
                <h5 class="text-danger mb-1">Error</h5>
                <p class="mb-0">${message}</p>
              </div>
            </div>
          </div>
        </div>
      `;
    }