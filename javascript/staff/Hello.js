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
      const response = await fetch('/api/check-role', {
          credentials: 'include',
          headers: {
              'Authorization': `Bearer ${token}`
          }
      });
      const data = await response.json();
      
      if (data.role !== 'staff') {
          window.location.href = '/index.html';
      }
  } catch (error) {
      console.error('Auth check failed:', error);
      window.location.href = '/index.html';
  }
}



      checkRole();