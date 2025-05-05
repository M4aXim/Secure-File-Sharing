(async function() {
    // Get token from localStorage or prompt
    const token = localStorage.getItem('jwtToken') || prompt('Enter JWT token');
    if (token) {
      localStorage.setItem('jwtToken', token);
    }
    
    // DOM elements
    const searchForm = document.getElementById('search-form');
    const usernameInput = document.getElementById('username');
    const searchButton = document.getElementById('search-button');
    const loadingEl = document.getElementById('loading');
    const emptyStateEl = document.getElementById('empty-state');
    const userCardEl = document.getElementById('user-card');
    const errorMessageEl = document.getElementById('error-message');
    const errorTextEl = document.getElementById('error-text');
    
    // User detail elements
    const userAvatarEl = document.getElementById('user-avatar');
    const userNameEl = document.getElementById('user-name');
    const userMetaEl = document.getElementById('user-meta');
    const userRoleEl = document.getElementById('user-role');
    const lastActivityEl = document.getElementById('last-activity');
    const detailUsernameEl = document.getElementById('detail-username');
    const detailEmailEl = document.getElementById('detail-email');
    const detailRoleEl = document.getElementById('detail-role');
    const detailCreatedEl = document.getElementById('detail-created');
    const detailLastActivityEl = document.getElementById('detail-last-activity');
    const jsonViewEl = document.getElementById('json-view');
    
    // Stats elements
    const ownedFoldersCountEl = document.getElementById('owned-folders-count');
    const sharedFoldersCountEl = document.getElementById('shared-folders-count');
    const pendingInvitationsCountEl = document.getElementById('pending-invitations-count');
    
    // Folders elements
    const ownedFoldersListEl = document.getElementById('owned-folders-list');
    const sharedFoldersListEl = document.getElementById('shared-folders-list');
    const pendingInvitationsListEl = document.getElementById('pending-invitations-list');
    
    // Activity log element
    const activityLogEl = document.getElementById('activity-log');
    
    // Tab functionality
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        // Remove active class from all tabs and contents
        tabs.forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        // Add active class to clicked tab and corresponding content
        tab.classList.add('active');
        const tabName = tab.getAttribute('data-tab');
        document.querySelector(`.tab-content[data-tab-content="${tabName}"]`).classList.add('active');
      });
    });
    
    // Format date function
    function formatDate(dateString) {
      if (!dateString) return 'Never';
      const date = new Date(dateString);
      const options = { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' };
      return date.toLocaleDateString('en-US', options);
    }
    
    // Format relative time
    function formatRelativeTime(dateString) {
      if (!dateString) return '';
      
      const date = new Date(dateString);
      const now = new Date();
      const diffSeconds = Math.floor((now - date) / 1000);
      
      if (diffSeconds < 60) {
        return 'just now';
      } else if (diffSeconds < 3600) {
        const minutes = Math.floor(diffSeconds / 60);
        return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
      } else if (diffSeconds < 86400) {
        const hours = Math.floor(diffSeconds / 3600);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
      } else if (diffSeconds < 604800) {
        const days = Math.floor(diffSeconds / 86400);
        return `${days} day${days > 1 ? 's' : ''} ago`;
      } else {
        return formatDate(dateString);
      }
    }
    
    // Generate avatar initial from username
    function getInitial(username) {
      return username.charAt(0).toUpperCase();
    }
    
    // Show error message
    function showError(message) {
      errorTextEl.textContent = message;
      errorMessageEl.style.display = 'block';
      setTimeout(() => {
        errorMessageEl.style.display = 'none';
      }, 5000);
    }
    
    // Reset UI state
    function resetUI() {
      loadingEl.style.display = 'none';
      userCardEl.style.display = 'none';
      emptyStateEl.style.display = 'block';
      errorMessageEl.style.display = 'none';
    }
    
    // Render owned folders
    function renderOwnedFolders(folders) {
      if (!folders || folders.length === 0) {
        ownedFoldersListEl.innerHTML = '<div class="empty-state"><p>No owned folders found</p></div>';
        return;
      }
      
      ownedFoldersListEl.innerHTML = '';
      folders.forEach(folder => {
        const folderEl = document.createElement('div');
        folderEl.className = 'folder-item';
        folderEl.innerHTML = `
          <div>
            <div class="folder-name">
              <i class="fas fa-folder"></i>
              ${folder.folderName}
              <span class="folder-badge ${folder.isPublic ? 'folder-badge-public' : 'folder-badge-private'}">
                ${folder.isPublic ? 'Public' : 'Private'}
              </span>
            </div>
            <div class="folder-meta">
              Created: ${formatDate(folder.createdAt)} | Friends: ${folder.friendCount || 0}
            </div>
          </div>
          <div>
            <span class="folder-meta">ID: ${folder.folderId}</span>
          </div>
        `;
        ownedFoldersListEl.appendChild(folderEl);
      });
    }
    
    // Render shared folders
    function renderSharedFolders(folders) {
      if (!folders || folders.length === 0) {
        sharedFoldersListEl.innerHTML = '<div class="empty-state"><p>No shared folders found</p></div>';
        return;
      }
      
      sharedFoldersListEl.innerHTML = '';
      folders.forEach(folder => {
        const folderEl = document.createElement('div');
        folderEl.className = 'folder-item';
        folderEl.innerHTML = `
          <div>
            <div class="folder-name">
              <i class="fas fa-folder-open"></i>
              ${folder.folderName}
            </div>
            <div class="folder-meta">
              Owner: ${folder.owner} | Permissions: ${folder.permissions}
            </div>
          </div>
          <div>
            <span class="folder-meta">ID: ${folder.folderId}</span>
          </div>
        `;
        sharedFoldersListEl.appendChild(folderEl);
      });
    }
    
    // Render pending invitations
    function renderPendingInvitations(invitations) {
      if (!invitations || invitations.length === 0) {
        pendingInvitationsListEl.innerHTML = '<div class="empty-state"><p>No pending invitations found</p></div>';
        return;
      }
      
      pendingInvitationsListEl.innerHTML = '';
      invitations.forEach(invitation => {
        const invitationEl = document.createElement('div');
        invitationEl.className = 'folder-item';
        invitationEl.innerHTML = `
          <div>
            <div class="folder-name">
              <i class="fas fa-envelope"></i>
              ${invitation.folderName}
            </div>
            <div class="folder-meta">
              From: ${invitation.owner}
            </div>
          </div>
          <div>
            <span class="folder-meta">Invitation ID: ${invitation.invitationId}</span>
          </div>
        `;
        pendingInvitationsListEl.appendChild(invitationEl);
      });
    }
    
    // Render activity log
// Render activity log
function renderActivityLog(activities) {
if (!activities || activities.length === 0) {
  activityLogEl.innerHTML = '<div class="empty-state"><p>No recent activity found</p></div>';
  return;
}

activityLogEl.innerHTML = '';
activities.forEach(activity => {
  const activityEl = document.createElement('div');
  activityEl.className = 'activity-item';
  
  // Determine icon based on activity type
  let actionIcon = 'fa-circle';
  const activityType = activity.activity || activity.action;
  
  if (activityType) {
    if (activityType.includes('login')) actionIcon = 'fa-sign-in-alt';
    if (activityType.includes('folder')) actionIcon = 'fa-folder';
    if (activityType.includes('file')) actionIcon = 'fa-file';
    if (activityType.includes('share')) actionIcon = 'fa-share-alt';
    if (activityType.includes('invite')) actionIcon = 'fa-envelope';
    if (activityType.includes('delete')) actionIcon = 'fa-trash';
  }
  
  // Use the correct field names from the API response
  const timestamp = activity.timestamp;
  const action = activity.activity || activity.action;
  
  // Format the details as needed
  let details = '';
  if (activity.folderId) {
    details += `Folder ID: ${activity.folderId}`;
  }
  if (activity.filename) {
    details += details ? ' | ' : '';
    details += `File: ${activity.filename}`;
  }
  if (activity.ip) {
    details += details ? ' | ' : '';
    details += `IP: ${activity.ip}`;
  }
  
  activityEl.innerHTML = `
    <div class="activity-time">${formatDate(timestamp)}</div>
    <div class="activity-action">
      <i class="fas ${actionIcon}"></i>
      ${action}
    </div>
    ${details ? `<div class="activity-details">${details}</div>` : ''}
  `;
  activityLogEl.appendChild(activityEl);
});
}

    
    // Handle form submission
    searchForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const username = usernameInput.value.trim();
      if (!username) return;
      
      // Update UI state
      errorMessageEl.style.display = 'none';
      emptyStateEl.style.display = 'none';
      userCardEl.style.display = 'none';
      loadingEl.style.display = 'block';
      
      try {
        const response = await fetch(`/api/staff/users/${username}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(errorText || `Failed to fetch user: ${response.status}`);
        }
        
        const data = await response.json();
        
        // Update basic user info
        userAvatarEl.textContent = getInitial(data.username);
        userNameEl.textContent = data.username;
        userMetaEl.textContent = `Joined on ${formatDate(data.createdAt)}`;
        userRoleEl.textContent = data.role;
        
        if (data.lastActivity) {
          lastActivityEl.textContent = `Last seen ${formatRelativeTime(data.lastActivity)}`;
        } else {
          lastActivityEl.textContent = '';
        }
        
        // Update user details
        detailUsernameEl.textContent = data.username;
        detailEmailEl.textContent = data.email;
        detailRoleEl.textContent = data.role;
        detailCreatedEl.textContent = formatDate(data.createdAt);
        detailLastActivityEl.textContent = data.lastActivity ? formatDate(data.lastActivity) : 'Never';
        
        // Update stats
        ownedFoldersCountEl.textContent = data.stats.ownedFolderCount;
        sharedFoldersCountEl.textContent = data.stats.sharedFolderCount;
        pendingInvitationsCountEl.textContent = data.stats.pendingInvitationCount;
        
        // Render folders
        renderOwnedFolders(data.ownedFolders);
        renderSharedFolders(data.sharedFolders);
        renderPendingInvitations(data.pendingInvitations);
        
        // Render activity log
        renderActivityLog(data.recentActivity);
        
        // Update JSON view
        jsonViewEl.textContent = JSON.stringify(data, null, 2);
          
// Show user card
loadingEl.style.display = 'none';
userCardEl.style.display = 'block';

} catch (error) {
console.error('Error:', error);
loadingEl.style.display = 'none';
emptyStateEl.style.display = 'block';
showError(error.message || 'Failed to fetch user data');
}
});

// Initialize the page
resetUI();

// Focus the username input
usernameInput.focus();
})();