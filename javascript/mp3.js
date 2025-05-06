    // Get query params
    const params = new URLSearchParams(window.location.search);
    const folderID = params.get('folderID');
    const filename = params.get('filename');
    if (!folderID || !filename) {
      alert('Missing folderID or filename');
      throw 'Missing params';
    }

    // DOM elements
    const audio = document.getElementById('audio');
    const playBtn = document.getElementById('playBtn');
    const playIcon = document.getElementById('playIcon');
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const currentTimeEl = document.getElementById('currentTime');
    const durationEl = document.getElementById('duration');
    const volumeSlider = document.getElementById('volumeSlider');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const rewindBtn = document.getElementById('rewindBtn');
    const forwardBtn = document.getElementById('forwardBtn');
    const trackInfoContainer = document.querySelector('.track-info');

    // Show title
    const audioTitle = document.getElementById('audioTitle');
    const decodedName = decodeURIComponent(filename);
    audioTitle.textContent = decodedName;
    document.title = `Playing: ${decodedName}`;

    // Build API URL
    const audioUrl = `/api/view-file/${encodeURIComponent(folderID)}/${encodeURIComponent(filename)}`;

    // Fetch with auth and set as audio source
    const xhr = new XMLHttpRequest();
    xhr.open('GET', audioUrl);
    xhr.setRequestHeader('Authorization', `Bearer ${localStorage.getItem('jwtToken')}`);
    xhr.responseType = 'blob';
    xhr.onload = () => {
      if (xhr.status === 200) {
        const blob = xhr.response;
        const objectUrl = URL.createObjectURL(blob);
        audio.src = objectUrl;
        
        // Initialize after audio is loaded
        audio.addEventListener('loadedmetadata', initializePlayer);
      } else {
        audioTitle.textContent = `Error: Failed to load audio (${xhr.status})`;
      }
    };
    xhr.onerror = () => {
      audioTitle.textContent = 'Network error while loading audio';
    };
    xhr.send();

    // Initialize player
    function initializePlayer() {
      // Format duration
      durationEl.textContent = formatTime(audio.duration);
      
      // Event listeners
      audio.addEventListener('timeupdate', updateProgress);
      audio.addEventListener('ended', audioEnded);
      playBtn.addEventListener('click', togglePlay);
      progressContainer.addEventListener('click', setProgress);
      volumeSlider.addEventListener('input', setVolume);
      prevBtn.addEventListener('click', () => skipTo(-30));
      nextBtn.addEventListener('click', () => skipTo(30));
      rewindBtn.addEventListener('click', () => skipTo(-10));
      forwardBtn.addEventListener('click', () => skipTo(10));
      
      // Set initial volume
      audio.volume = volumeSlider.value;
    }

    // Toggle play/pause
    function togglePlay() {
      if (audio.paused) {
        audio.play();
        playIcon.classList.replace('fa-play', 'fa-pause');
        trackInfoContainer.classList.add('playing');
      } else {
        audio.pause();
        playIcon.classList.replace('fa-pause', 'fa-play');
        trackInfoContainer.classList.remove('playing');
      }
    }

    // Update progress bar
    function updateProgress() {
      const progress = (audio.currentTime / audio.duration) * 100;
      progressBar.style.width = `${progress}%`;
      currentTimeEl.textContent = formatTime(audio.currentTime);
    }

    // Set progress when clicking on progress bar
    function setProgress(e) {
      const width = this.clientWidth;
      const clickX = e.offsetX;
      const duration = audio.duration;
      audio.currentTime = (clickX / width) * duration;
    }

    // Set volume
    function setVolume() {
      audio.volume = volumeSlider.value;
      
      // Update volume icon
      const volumeIcon = document.querySelector('.volume-icon');
      if (audio.volume === 0) {
        volumeIcon.className = 'fas fa-volume-mute volume-icon';
      } else if (audio.volume < 0.5) {
        volumeIcon.className = 'fas fa-volume-down volume-icon';
      } else {
        volumeIcon.className = 'fas fa-volume-up volume-icon';
      }
    }

    // Skip forward or backward
    function skipTo(seconds) {
      audio.currentTime = Math.max(0, Math.min(audio.duration, audio.currentTime + seconds));
    }

    // Handle audio ended
    function audioEnded() {
      playIcon.classList.replace('fa-pause', 'fa-play');
      trackInfoContainer.classList.remove('playing');
      progressBar.style.width = '0%';
    }

    // Format time to MM:SS
    function formatTime(seconds) {
      const min = Math.floor(seconds / 60);
      const sec = Math.floor(seconds % 60);
      return `${min}:${sec < 10 ? '0' + sec : sec}`;
    }

    // Keyboard controls
    document.addEventListener('keydown', (e) => {
      switch(e.key) {
        case ' ':
          e.preventDefault();
          togglePlay();
          break;
        case 'ArrowRight':
          skipTo(10);
          break;
        case 'ArrowLeft':
          skipTo(-10);
          break;
        case 'ArrowUp':
          volumeSlider.value = Math.min(1, parseFloat(volumeSlider.value) + 0.1);
          setVolume();
          break;
        case 'ArrowDown':
          volumeSlider.value = Math.max(0, parseFloat(volumeSlider.value) - 0.1);
          setVolume();
          break;
      }
    });