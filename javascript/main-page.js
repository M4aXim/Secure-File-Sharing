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
      document.getElementById('otp-login-form').classList.add('hidden');
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

// Google login functionality
document.addEventListener('DOMContentLoaded', function() {
  const googleLoginBtn = document.getElementById('googleLoginBtn');
  if (googleLoginBtn) {
    googleLoginBtn.addEventListener('click', function() {
      // Direct navigation to Google OAuth endpoint
      window.location.href = '/api/auth/google';
    });
  }
  
  // Check if we're on the login success page with a token
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('token');
  
  if (token) {
    // Store the token in localStorage
    localStorage.setItem('jwtToken', token);
    showNotification('Google login successful! Redirecting...', 'is-success');
    
    // Get user info from token
    fetch('/api/verify-token', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => response.json())
    .then(data => {
      if (data.message === 'Token is valid') {
        // Try to decode the JWT to get user info (basic decoding, not verification)
        try {
          const base64Url = token.split('.')[1];
          const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
          const payload = JSON.parse(window.atob(base64));
          
          // Store user info
          localStorage.setItem('username', payload.username);
          localStorage.setItem('userRole', payload.role);
          
          console.log('Logged in as:', payload.username, 'with role:', payload.role);
        } catch (e) {
          console.error('Error decoding token:', e);
        }
        
        // Redirect to dashboard
        setTimeout(() => {
          window.location.href = '/dashboard/dashboard.html';
        }, 1500);
      } else {
        showNotification('Invalid token. Please try again.', 'is-danger');
      }
    })
    .catch(error => {
      showNotification('Error verifying token. Please try again.', 'is-danger');
      console.error('Token verification error:', error);
    });
  }
});

// Function to request a one-time password
function requestOTP() {
  const email = document.getElementById('otp-email').value;
  
  if (!email) {
    showNotification('Please enter your email address', 'is-danger');
    return;
  }
  
  // Disable button and show loading state
  const button = document.getElementById('request-otp-button');
  const originalText = button.innerHTML;
  button.disabled = true;
  button.innerHTML = '<span class="icon"><i class="fas fa-spinner fa-spin"></i></span><span>Sending...</span>';
  
  fetch('/api/request-otp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email })
  })
  .then(response => response.json())
  .then(data => {
    button.disabled = false;
    button.innerHTML = originalText;
    
    if (data.message) {
      showNotification('If your email is registered, a one-time password has been sent', 'is-success');
      
      // Show the OTP entry section
      document.getElementById('request-otp-section').classList.add('is-hidden');
      document.getElementById('enter-otp-section').classList.remove('is-hidden');
      
      // Set the email in the confirmation field
      document.getElementById('confirm-otp-email').value = email;
      
      // Focus on the OTP input field
      document.getElementById('otp-code').focus();
    } else {
      showNotification(data.error || 'Failed to send OTP', 'is-danger');
    }
  })
  .catch(error => {
    button.disabled = false;
    button.innerHTML = originalText;
    showNotification('Connection error. Please try again later.', 'is-danger');
    console.error('Error:', error);
  });
}

// Function to login with a one-time password
function loginWithOTP() {
  const email = document.getElementById('confirm-otp-email').value;
  const otp = document.getElementById('otp-code').value;
  
  if (!email || !otp) {
    showNotification('Please enter the one-time password', 'is-danger');
    return;
  }
  
  if (otp.length !== 6 || isNaN(otp)) {
    showNotification('Please enter a valid 6-digit code', 'is-danger');
    return;
  }
  
  fetch('/api/login-with-otp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email, otp })
  })
  .then(response => response.json())
  .then(data => {
    if (data.token) {
      // Store the token in localStorage
      localStorage.setItem('jwtToken', data.token);
      
      // Also store user info if available
      if (data.user) {
        localStorage.setItem('username', data.user.username);
        localStorage.setItem('userRole', data.user.role);
      }
      
      showNotification('Login successful! Redirecting...', 'is-success');
      
      setTimeout(() => {
        window.location.href = '/dashboard/dashboard.html';
      }, 1500);
    } else {
      showNotification(data.error || 'Invalid one-time password', 'is-danger');
    }
  })
  .catch(error => {
    showNotification('Connection error. Please try again later.', 'is-danger');
    console.error('Error:', error);
  });
}

// Function to reset the OTP form to the email input stage
function resetOTPForm() {
  // Show the request section and hide the enter section
  document.getElementById('request-otp-section').classList.remove('is-hidden');
  document.getElementById('enter-otp-section').classList.add('is-hidden');
  
  // Clear the OTP input
  document.getElementById('otp-code').value = '';
  
  // Focus on the email input
  document.getElementById('otp-email').focus();
}