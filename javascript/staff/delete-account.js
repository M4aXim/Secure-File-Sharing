document.getElementById('delete-account-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const targetUsername = document.getElementById('targetUsername').value;
    const confirmation = document.getElementById('confirmation').value;
    const reason = document.getElementById('reason').value;
    const resultMessage = document.getElementById('result-message');
    
    resultMessage.classList.remove('hidden', 'is-danger', 'is-success');
    
    // Validate confirmation
    if (targetUsername !== confirmation) {
        resultMessage.textContent = 'Username confirmation does not match.';
        resultMessage.classList.add('is-danger');
        resultMessage.classList.remove('hidden');
        return;
    }
    
    // Validate reason
    if (!reason || !['policy_violation', 'user_request'].includes(reason)) {
        resultMessage.textContent = 'Valid reason is required: "policy_violation" or "user_request"';
        resultMessage.classList.add('is-danger');
        resultMessage.classList.remove('hidden');
        return;
    }

    const token = localStorage.getItem('jwtToken');
    
    try {
        const response = await fetch('/api/owner/delete-account', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ targetUsername, reason })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            resultMessage.textContent = `Success: ${data.message}. User ${data.username} deleted with ${data.foldersRemoved} folders removed.`;
            resultMessage.classList.add('is-success');
            document.getElementById('delete-account-form').reset();
        } else {
            resultMessage.textContent = `Error: ${data.message || 'Failed to delete account'}`;
            resultMessage.classList.add('is-danger');
        }
    } catch (err) {
        resultMessage.textContent = 'Error: Could not connect to server';
        resultMessage.classList.add('is-danger');
    }
    
    resultMessage.classList.remove('hidden');
});
