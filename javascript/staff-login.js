document.getElementById('login').addEventListener('click', async () => {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        
        if (response.ok) {
            localStorage.setItem('jwtToken', data.token);
            if (data.user.role === 'staff') {
                window.location.href = '/staff/Hello.html';
            } else {
                window.location.href = '/index.html';
            }
        } else {
            alert(data.error);
        }
    } catch (err) {
        alert('Error during login');
    }
});