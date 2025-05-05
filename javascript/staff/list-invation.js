(async function(){
    const token = localStorage.getItem('jwtToken') || prompt('Enter JWT token');
    const statusMessage = document.getElementById('statusMessage');
    const statusMessageText = document.getElementById('statusMessageText');
    const emptyState = document.getElementById('emptyState');
    const invitationCount = document.getElementById('invitationCount');
    
    document.getElementById('loadBtn').onclick = async () => {
      try {
        // Show loading state
        statusMessage.style.display = 'block';
        statusMessageText.textContent = 'Loading invitations...';
        statusMessage.className = 'notification is-info is-light mb-4';
        
        const res = await fetch('/api/staff/invitations', {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        
        if (!res.ok) throw new Error(await res.text());
        
        const data = await res.json();
        const ul = document.getElementById('invitations');
        ul.innerHTML = '';
        
        if (data.length === 0) {
          emptyState.innerHTML = '<p class="has-text-grey">No pending invitations found.</p>';
          emptyState.style.display = 'block';
        } else {
          emptyState.style.display = 'none';
          
          data.forEach(inv => {
            const li = document.createElement('li');
            li.className = 'invitation-item card mb-3';
            li.innerHTML = `
              <div class="card-content">
                <div class="media">
                  <div class="media-left">
                    <span class="icon is-medium has-text-info">
                      <i class="fas fa-user-plus fa-lg"></i>
                    </span>
                  </div>
                  <div class="media-content">
                    <p class="is-size-6"><strong>Folder:</strong> ${inv.folderName}</p>
                    <p class="is-size-7 has-text-grey">
                      <span class="icon-text">
                        <span class="icon"><i class="fas fa-id-card"></i></span>
                        <span>Invitation ID: ${inv.invitationId}</span>
                      </span>
                    </p>
                  </div>
                </div>
                <div class="content is-small">
                  <div class="tags">
                    <span class="tag is-info is-light">
                      <span class="icon"><i class="fas fa-user"></i></span>
                      <span>Owner: ${inv.owner}</span>
                    </span>
                    </span>
                  </div>
                </div>
              </div>
            `;
            ul.appendChild(li);
          });
        }
        
        // Update counter
        invitationCount.textContent = data.length;
        
        // Show success message
        statusMessageText.textContent = `Successfully loaded ${data.length} invitation(s)`;
        statusMessage.className = 'notification is-success is-light mb-4';
        
        // Hide status message after 3 seconds
        setTimeout(() => {
          statusMessage.style.display = 'none';
        }, 3000);
        
      } catch (err) {
        statusMessage.className = 'notification is-danger is-light mb-4';
        statusMessageText.textContent = 'Error: ' + err.message;
      }
    };
  })();