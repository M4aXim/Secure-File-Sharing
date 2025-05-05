(async function(){
    // Get or request the JWT token
    const token = localStorage.getItem('jwtToken') || prompt('Enter JWT token');
    
    // Get DOM elements
    const form = document.getElementById('form');
    const resultContainer = document.getElementById('resultContainer');
    const resultNotification = document.getElementById('resultNotification');
    const resultElement = document.getElementById('result');
    const loadingIndicator = document.getElementById('loadingIndicator');
    
    // Handle form submission
    form.onsubmit = async e => {
      e.preventDefault();
      const folderId = document.getElementById('folderId').value.trim();
      
      if (!folderId) {
        showResult('Please enter a folder ID', 'is-warning');
        return;
      }
      
      // Show loading indicator
      loadingIndicator.style.display = 'block';
      resultContainer.style.display = 'none';
      
      try {
        const res = await fetch(`/api/staff/folders/${folderId}`, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + token }
        });
        
        const data = await res.json();
        
        if (!res.ok) {
          throw new Error(data.error || data.message || res.statusText);
        }
        
        // Show success message
        showResult(`<strong>Success!</strong> ${data.message || 'Folder deleted successfully.'}`, 'is-success');
        
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
      resultElement.innerHTML = message;
      resultNotification.className = `notification ${type} is-light`;
      resultContainer.style.display = 'block';
      
      // Scroll to result if it's not in view
      resultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  })();