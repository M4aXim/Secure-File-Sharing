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
      
      // Get folder ID
      const folderId = document.getElementById('folderId').value.trim();
      
      if (!folderId) {
        showResult('Please enter a folder ID', 'is-danger');
        return;
      }
      
      // Show loading indicator
      loadingIndicator.style.display = 'block';
      resultDiv.style.display = 'none';
      
      try {
        // Make API request
        const res = await fetch(`/api/staff/flag-folder/${folderId}`, {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + token }
        });
        
        // Parse response
        const data = await res.json();
        
        // Handle errors
        if (!res.ok) {
          throw new Error(data.error || data.message || res.statusText);
        }
        
        // Show success message
        showResult(`<strong>Success!</strong> ${data.message || 'Folder has been flagged.'}`, 'is-success');
        
        // Clear the form
        document.getElementById('folderId').value = '';
        
      } catch (err) {
        // Show error message
        showResult(`<strong>Error:</strong> ${err.message}`, 'is-danger');
      } finally {
        // Hide loading indicator
        loadingIndicator.style.display = 'none';
      }
    };
    
    // Helper function to show results
    function showResult(message, type = 'is-info') {
      resultMessage.innerHTML = message;
      resultDiv.className = `notification ${type}`;
      resultDiv.style.display = 'block';
      
      // Scroll to result if needed
      resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  })();