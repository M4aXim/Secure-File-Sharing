(async function(){
    // Get or request authentication token
    const token = localStorage.getItem('jwtToken') || prompt('Enter JWT token');
    
    // DOM elements
    const form = document.getElementById('form');
    const resultDiv = document.getElementById('result');
    const resultMessage = document.getElementById('resultMessage');
    const loadingIndicator = document.getElementById('loadingIndicator');
    
    // Form submission handler
    form.onsubmit = async e => {
      e.preventDefault();
      
      // Get form values
      const folderId = document.getElementById('folderId').value.trim();
      const friendUsername = document.getElementById('friendUsername').value.trim();
      
      // Show loading, hide any previous results
      loadingIndicator.style.display = 'block';
      resultDiv.style.display = 'none';
      
      try {
        // Make API request
        const res = await fetch(`/api/staff/folders/${folderId}/friends/${friendUsername}`, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + token }
        });
        
        // Parse the response data
        const data = await res.json();
        
        // Handle errors
        if (!res.ok) {
          throw new Error(data.error || data.message || res.statusText);
        }
        
        // Show success message
        resultMessage.innerHTML = `<strong>Success!</strong> ${data.message || 'Friend was removed from the folder.'}`;
        resultDiv.className = 'notification is-success';
        resultDiv.style.display = 'block';
        
        // Clear form inputs on success
        document.getElementById('friendUsername').value = '';
        
      } catch (err) {
        // Show error message
        resultMessage.innerHTML = `<strong>Error:</strong> ${err.message}`;
        resultDiv.className = 'notification is-danger';
        resultDiv.style.display = 'block';
      } finally {
        // Hide loading indicator
        loadingIndicator.style.display = 'none';
        
        // Scroll to result
        resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    };
  })();