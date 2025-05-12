function toggleDark() {
    document.body.classList.toggle('dark');
    localStorage.setItem('staff_darkmode', document.body.classList.contains('dark'));
  }

  if (localStorage.getItem('staff_darkmode') === 'true') {
    document.body.classList.add('dark');
  }

  async function checkRole() {
    try {
      const token = localStorage.getItem('jwtToken');
      if (!token) {
        window.location.href = '/index.html';
        return;
      }
      
      const response = await fetch('/api/check-role', {
        credentials: 'include',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to check role');
      }
      
      const data = await response.json();
      
      // Check if user is staff or owner
      if (data.role !== 'staff' && data.role !== 'owner') {
        window.location.href = '/index.html';
        return;
      }
      
      // Show owner tools if the user is the owner
      if (data.role === 'owner') {
        const ownerTools = document.getElementById('owner-tools');
        if (ownerTools) {
          ownerTools.style.display = 'block';
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      window.location.href = '/index.html';
    }
  }

  // Run the role check when the page loads
  document.addEventListener('DOMContentLoaded', checkRole);