document.getElementById('remove-friend-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const folderId = document.getElementById('folder-id').value.trim();
    const friendUsername = document.getElementById('friend-username').value.trim();
    const statusMessage = document.getElementById('status-message');
    const token = localStorage.getItem('jwtToken');
    
    try {
        const response = await fetch(`/api/staff/folders/${folderId}/friends/${friendUsername}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });
        
        const result = await response.json();
        
        statusMessage.classList.remove('hidden');
        
        // Updated to work with Bulma classes
        if (statusMessage.classList.contains('is-danger')) {
            statusMessage.classList.remove('is-danger');
        }
        if (statusMessage.classList.contains('is-success')) {
            statusMessage.classList.remove('is-success');
        }
        
        if (response.ok) {
            statusMessage.textContent = result.message;
            statusMessage.classList.add('is-success');
        } else {
            statusMessage.textContent = result.message || 'Failed to remove friend access';
            statusMessage.classList.add('is-danger');
        }
    } catch (error) {
        statusMessage.textContent = 'An error occurred. Please try again.';
        if (statusMessage.classList.contains('is-success')) {
            statusMessage.classList.remove('is-success');
        }
        statusMessage.classList.add('is-danger');
        console.error('Error:', error);
    }
    
    statusMessage.classList.remove('hidden');
})