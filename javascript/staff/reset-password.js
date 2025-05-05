(async function(){
    const token = localStorage.getItem('jwtToken') || prompt('Enter JWT token');
    document.getElementById('form').onsubmit = async e => {
      e.preventDefault();
      const resultEl = document.getElementById('result');
      resultEl.className = 'notification';
      resultEl.classList.add('is-hidden');
      
      const username = document.getElementById('username').value.trim();
      try {
        const res = await fetch(`/api/staff/reset-password/${username}`, {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || data.message || res.statusText);
        resultEl.textContent = data.message;
        resultEl.classList.add('is-success');
        resultEl.classList.remove('is-hidden', 'is-danger');
      } catch (err) {
        resultEl.textContent = 'Error: ' + err.message;
        resultEl.classList.add('is-danger');
        resultEl.classList.remove('is-hidden', 'is-success');
      }
    };
  })();