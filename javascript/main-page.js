function forgotPassword() {
  const email = prompt("Please enter your email address:");

  if (!email) {
    showNotification('Please enter email', 'is-danger');
    return;
  }

  fetch(`/api/change-password/${encodeURIComponent(email)}`, {
    method: 'POST' 
  })
  .then(response => response.json())
  .then(data => {
    if (data.message) {
      showNotification(data.message, 'is-success');
    } else {
      showNotification(data.error || 'Password reset failed', 'is-danger');
    }
  })
  .catch(error => {
    showNotification('Connection error. Please try again later.', 'is-danger');
  });
}

    function showForm(formId) {
      document.getElementById('login-form').classList.add('hidden');
      document.getElementById('register-form').classList.add('hidden');
      document.getElementById(formId + '-form').classList.remove('hidden');
      
      document.getElementById(formId + '-form').scrollIntoView({ behavior: 'smooth' });
    }
    
    function register() {
      const username = document.querySelector('#register-form input[type="text"]').value;
      const email = document.querySelector('#register-form input[type="email"]').value;
      const password = document.querySelector('#register-form input[type="password"]').value;
      
      if (!username || !email || !password) {
        showNotification('Please fill in all fields', 'is-danger');
        return;
      }
      
      if (password.length < 8) {
        showNotification('Password must be at least 8 characters', 'is-danger');
        return;
      }
      
      fetch('/api/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, email, password })
      })
      .then(response => {
        if (response.ok) {
          showNotification('Registration successful! Please log in.', 'is-success');
          setTimeout(() => {
            showForm('login');
          }, 2000);
        } else {
          showNotification('Registration failed. Please try again.', 'is-danger');
        }
      })
      .catch(error => {
        showNotification('Connection error. Please try again later.', 'is-danger');
      });
    }
    
    function login() {
      const username = document.querySelector('#login-form input[type="text"]').value;
      const password = document.querySelector('#login-form input[type="password"]').value;
      const mfaTokenInput = document.querySelector('#login-form input[name="mfaToken"]');
      const mfaToken = mfaTokenInput ? mfaTokenInput.value : null;
      
      if (!username || !password) {
        showNotification('Please fill in all fields', 'is-danger');
        return;
      }
      
      fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password, token: mfaToken })
      })
      .then(response => response.json())
      .then(data => {
        if (data.token) {
          // Store the token in localStorage
          localStorage.setItem('jwtToken', data.token);
          showNotification('Login successful! Redirecting...', 'is-success');
          setTimeout(() => {
            window.location.href = '/dashboard/dashboard.html';
          }, 1500);
        } else if (data.error === 'MFA token required') {
          // Show MFA token input field if MFA is enabled
          showMFATokenInput(username, password);
        } else {
          showNotification(data.error || 'Invalid username or password', 'is-danger');
        }
      })
      .catch(error => {
        showNotification('Connection error. Please try again later.', 'is-danger');
      });
    }
    
    // Function to show MFA token input when needed
    function showMFATokenInput(username, password) {
      // Check if MFA field already exists
      let mfaField = document.querySelector('#mfa-field');
      
      if (!mfaField) {
        // Create MFA input field
        const passwordField = document.querySelector('#login-form .field:nth-child(2)');
        
        mfaField = document.createElement('div');
        mfaField.className = 'field';
        mfaField.id = 'mfa-field';
        
        mfaField.innerHTML = `
          <label class="label">Authentication Code</label>
          <div class="control has-icons-left">
            <input class="input" type="text" name="mfaToken" placeholder="Enter 6-digit code" maxlength="6">
            <span class="icon is-small is-left field-icon">
              <i class="fas fa-shield-alt"></i>
            </span>
          </div>
          <p class="help">Enter the verification code from your authenticator app</p>
        `;
        
        // Insert after password field
        passwordField.parentNode.insertBefore(mfaField, passwordField.nextSibling);
        
        // Focus on the MFA field
        document.querySelector('input[name="mfaToken"]').focus();
        
        // Show notification
        showNotification('Please enter your authentication code', 'is-info');
      }
    }
    
    function showNotification(message, type) {
      const existingNotifications = document.querySelectorAll('.notification');
      existingNotifications.forEach(notification => {
        notification.remove();
      });
      
      const notification = document.createElement('div');
      notification.className = `notification ${type} is-light`;
      notification.style.position = 'fixed';
      notification.style.top = '20px';
      notification.style.right = '20px';
      notification.style.maxWidth = '300px';
      notification.style.zIndex = '1000';
      notification.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
      notification.style.borderRadius = '6px';
      
      // Add close button
      const closeButton = document.createElement('button');
      closeButton.className = 'delete';
      closeButton.addEventListener('click', () => {
        notification.remove();
      });
      
      notification.appendChild(closeButton);
      notification.appendChild(document.createTextNode(message));
      document.body.appendChild(notification);
      
      setTimeout(() => {
        notification.remove();
      }, 4000);
    }