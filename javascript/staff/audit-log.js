(async function(){
    const statusEl = document.getElementById('status');
    const statusMessageEl = document.getElementById('status-message');
    
    // Check for token
    const token = localStorage.getItem('jwtToken') || prompt('Enter JWT token');
    if (!token) {
      showStatus('No authentication token provided', 'is-danger');
    }

    // Form submission
    document.getElementById('form').onsubmit = async e => {
      e.preventDefault();
      const limit = document.getElementById('limit').value;
      
      // Show loading state
      showStatus('Fetching audit logs...', 'is-info');
      
      try {
        const res = await fetch(`/api/staff/audit-log?limit=${limit}`, {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        
        if (!res.ok) {
          const errorText = await res.text();
          throw new Error(errorText || `HTTP error ${res.status}`);
        }
        
        const data = await res.json();
        document.getElementById('output').textContent = JSON.stringify(data, null, 2);
        showStatus(`Successfully loaded ${Object.keys(data).length > 0 ? data.length || 'all' : '0'} audit logs`, 'is-success');
        
        // Hide status after success
        setTimeout(() => {
          statusEl.style.display = 'none';
        }, 3000);
        
      } catch (err) {
        document.getElementById('output').textContent = 'Error: ' + err.message;
        showStatus('Error fetching logs: ' + err.message, 'is-danger');
      }
    };
    
    // Helper to show status messages
    function showStatus(message, type = 'is-info') {
      statusEl.className = 'notification ' + type;
      statusMessageEl.textContent = message;
      statusEl.style.display = 'block';
    }
  })();