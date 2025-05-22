const params = new URLSearchParams(window.location.search);
const folderID = params.get('folderID');
const filename = params.get('filename');
if (!folderID || !filename) {
  alert('Missing folderID or filename');
  throw 'Missing params';
}

// Display filename in title
const videoTitle = document.getElementById('videoTitle');
videoTitle.textContent = decodeURIComponent(filename);
document.title = `Playing: ${decodeURIComponent(filename)}`;

// Elements
const video = document.getElementById('video');
const playPause = document.getElementById('playPause');
const playPauseIcon = document.getElementById('playPauseIcon');
const volBar = document.getElementById('volBar');
const volIcon = document.getElementById('volIcon');
const muteBtn = document.getElementById('muteBtn');
const fullScreen = document.getElementById('fullScreen');
const loadingIndicator = document.getElementById('loadingIndicator');
const currentTimeDisplay = document.getElementById('currentTime');
const durationDisplay = document.getElementById('duration');
const progressBar = document.getElementById('progressBar');
const bufferedBar = document.getElementById('bufferedBar');
const seekContainer = document.getElementById('seekContainer');
const speedOptions = document.getElementById('speedOptions');
const currentSpeed = document.getElementById('currentSpeed');
const pipBtn = document.getElementById('pipBtn');
const mainPlayerContainer = document.getElementById('mainPlayerContainer');
const helpBtn = document.getElementById('helpBtn');
const keyboardInfo = document.getElementById('keyboardInfo');
const screenshotBtn = document.getElementById('screenshotBtn');
const notificationArea = document.getElementById('notificationArea');
const loopBtn = document.getElementById('loopBtn');
const jumpPrev = document.getElementById('jumpPrev');
const jumpNext = document.getElementById('jumpNext');
const subtitleBtn = document.getElementById('subtitleBtn');
const subtitleMenu = document.getElementById('subtitleMenu');
const subtitleOptions = document.getElementById('subtitleOptions');
const subtitleFile = document.getElementById('subtitleFile');

// Point at your existing API endpoint
const videoSrc = `/api/view-file/${encodeURIComponent(folderID)}/${encodeURIComponent(filename)}`;

// Create a video source with credentials
const xhr = new XMLHttpRequest();
xhr.open('GET', videoSrc);
xhr.setRequestHeader('Authorization', `Bearer ${localStorage.getItem('jwtToken')}`);
xhr.responseType = 'blob';

// Load video
xhr.onload = function() {
  if (xhr.status === 200) {
    const videoBlob = xhr.response;
    const videoObjectUrl = URL.createObjectURL(videoBlob);
    video.src = videoObjectUrl;
    
    // Try to load subtitle with same name
    tryLoadMatchingSubtitles();
    
    try {
      storeVideoBlob(videoBlob, `${folderID}_${filename}`);
    } catch (e) {
      console.error('Failed to store blob:', e);
    }
  }
};
xhr.send();

// Try to find and load matching subtitles
function tryLoadMatchingSubtitles() {
  const baseFilename = decodeURIComponent(filename).replace(/\.[^/.]+$/, '');
  const srtFile = `${baseFilename}.srt`;
  const vttFile = `${baseFilename}.vtt`;
  
  // Try SRT first
  fetch(`/api/view-file/${encodeURIComponent(folderID)}/${encodeURIComponent(srtFile)}`, {
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('jwtToken')}`
    }
  })
  .then(response => {
    if (response.ok) return response.blob();
    throw new Error('SRT not found');
  })
  .then(subtitleBlob => {
    addSubtitleTrack(subtitleBlob, 'Auto-detected SRT', 'en');
    showNotification('Subtitles automatically loaded');
  })
  .catch(() => {
    // Try VTT if SRT failed
    fetch(`/api/view-file/${encodeURIComponent(folderID)}/${encodeURIComponent(vttFile)}`, {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('jwtToken')}`
      }
    })
    .then(response => {
      if (response.ok) return response.blob();
      throw new Error('VTT not found');
    })
    .then(subtitleBlob => {
      addSubtitleTrack(subtitleBlob, 'Auto-detected VTT', 'en');
      showNotification('Subtitles automatically loaded');
    })
    .catch(() => {
      // Silent fail - no subtitles found
      console.log('No matching subtitle files found');
    });
  });
}

// Add subtitle track to video
function addSubtitleTrack(blob, label, language) {
  const url = URL.createObjectURL(blob);
  const track = document.createElement('track');
  track.kind = 'subtitles';
  track.label = label;
  track.srclang = language;
  track.src = url;
  
  video.appendChild(track);
  
  // Add to options menu
  const option = document.createElement('div');
  option.className = 'subtitle-option';
  option.setAttribute('data-value', label);
  option.textContent = label;
  subtitleOptions.appendChild(option);
  
  // Auto-select this track
  setTimeout(() => {
    for (const track of video.textTracks) {
      if (track.label === label) {
        track.mode = 'showing';
        activeSubtitleTrack = track;
        
        // Update UI
        document.querySelectorAll('.subtitle-option').forEach(opt => {
          opt.classList.toggle('active', opt.getAttribute('data-value') === label);
        });
        
        break;
      }
    }
  }, 100);
}

// IndexedDB functions
function openVideoDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('VideoPlayerDB', 1);
    request.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('videos')) {
        db.createObjectStore('videos');
      }
    };
    request.onsuccess = e => resolve(e.target.result);
    request.onerror = e => reject(e.target.error);
  });
}
function storeVideoBlob(blob, key) {
  openVideoDatabase().then(db => {
    const transaction = db.transaction(['videos'], 'readwrite');
    const store = transaction.objectStore('videos');
    const request = store.put(blob, key);
    request.onsuccess = () => {
      localStorage.setItem('currentVideoKey', key);
      localStorage.setItem('currentVideoTitle', videoTitle.textContent);
    };
    request.onerror = e => console.error('Error storing video blob:', e.target.error);
  });
}
function getVideoBlob(key) {
  return new Promise((resolve, reject) => {
    openVideoDatabase().then(db => {
      const transaction = db.transaction(['videos'], 'readonly');
      const store = transaction.objectStore('videos');
      const request = store.get(key);
      request.onsuccess = e => {
        if (e.target.result) resolve(e.target.result);
        else reject(new Error('Video blob not found'));
      };
      request.onerror = e => reject(e.target.error);
    });
  });
}

// Loading indicator
video.addEventListener('waiting', () => loadingIndicator.style.display = 'block');
video.addEventListener('canplay', () => loadingIndicator.style.display = 'none');

// Time formatting
function formatTime(seconds) {
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  if (hrs > 0) {
    return `${hrs}:${mins.toString().padStart(2,'0')}:${secs.toString().padStart(2,'0')}`;
  } else {
    return `${mins}:${secs.toString().padStart(2,'0')}`;
  }
}

// Metadata loaded
video.addEventListener('loadedmetadata', () => {
  durationDisplay.textContent = formatTime(video.duration);
  const saved = localStorage.getItem(`videoPosition_${folderID}_${filename}`);
  if (saved) {
    const pos = parseFloat(saved);
    if (pos > 0 && pos < video.duration - 5) {
      video.currentTime = pos;
      showNotification(`Resumed from ${formatTime(pos)}`);
    }
  }
});

// Time update
video.addEventListener('timeupdate', () => {
  currentTimeDisplay.textContent = formatTime(video.currentTime);
  const pct = (video.currentTime / video.duration) * 100;
  progressBar.style.width = `${pct}%`;
  localStorage.setItem(`videoPosition_${folderID}_${filename}`, video.currentTime);
});

// Buffered update
video.addEventListener('progress', () => {
  if (video.buffered.length) {
    const end = video.buffered.end(video.buffered.length - 1);
    const pct = (end / video.duration) * 100;
    bufferedBar.style.width = `${pct}%`;
  }
});

// Seek container click
seekContainer.addEventListener('click', e => {
  const rect = seekContainer.getBoundingClientRect();
  const pos = (e.clientX - rect.left) / rect.width;
  video.currentTime = pos * video.duration;
});

// Drag handle
let isDragging = false;
seekContainer.addEventListener('mousedown', e => {
  isDragging = true;
  if (!video.paused) { video.pause(); window.resumeAfterDrag = true; }
  updateSeek(e);
});
document.addEventListener('mousemove', e => {
  if (isDragging) {
    updateSeek(e);
    e.preventDefault();
  }
});
document.addEventListener('mouseup', () => {
  if (isDragging && window.resumeAfterDrag) {
    video.play();
    window.resumeAfterDrag = false;
  }
  isDragging = false;
});
function updateSeek(e) {
  const rect = seekContainer.getBoundingClientRect();
  let pos = (e.clientX - rect.left) / rect.width;
  pos = Math.max(0, Math.min(1, pos));
  video.currentTime = pos * video.duration;
}

// Play/pause
playPause.onclick = togglePlayPause;
video.onclick = e => e.target === video && togglePlayPause();
function togglePlayPause() {
  video.paused ? video.play() : video.pause();
}
video.onplay = () => playPauseIcon.className = 'fas fa-pause';
video.onpause = () => playPauseIcon.className = 'fas fa-play';

// Volume
volBar.oninput = () => {
  video.volume = volBar.value;
  updateVolIcon();
  localStorage.setItem('mp4viewer_volume', video.volume);
};
function updateVolIcon() {
  if (video.muted || video.volume === 0) volIcon.className = 'fas fa-volume-mute';
  else if (video.volume < 0.5) volIcon.className = 'fas fa-volume-down';
  else volIcon.className = 'fas fa-volume-up';
}
muteBtn.onclick = () => {
  video.muted = !video.muted;
  localStorage.setItem('mp4viewer_muted', video.muted);
  updateVolIcon();
};

// Fullscreen
fullScreen.onclick = () => {
  if (!document.fullscreenElement) {
    mainPlayerContainer.requestFullscreen().catch(err => showNotification(`Error: ${err.message}`));
  } else {
    document.exitFullscreen();
  }
};

// Speed control
speedOptions.addEventListener('click', e => {
  if (e.target.classList.contains('speed-option')) {
    const speed = parseFloat(e.target.getAttribute('data-speed'));
    video.playbackRate = speed;
    currentSpeed.textContent = `${speed}x`;
    document.querySelectorAll('.speed-option').forEach(opt => opt.classList.remove('active'));
    e.target.classList.add('active');
    localStorage.setItem('mp4viewer_speed', speed);
    showNotification(`Speed: ${speed}x`);
  }
});

// Picture-in-picture
pipBtn.addEventListener('click', togglePictureInPicture);
async function togglePictureInPicture() {
  try {
    if (document.pictureInPictureElement) {
      await document.exitPictureInPicture();
    } else if (document.pictureInPictureEnabled) {
      await video.requestPictureInPicture();
      pipBtn.classList.add('pip-active');
      showNotification('Picture-in-Picture mode active');
      window.addEventListener('beforeunload', () => {
        localStorage.setItem('pip_time', video.currentTime);
        localStorage.setItem('pip_isPlaying', !video.paused);
      });
    } else {
      showNotification('Picture-in-Picture not supported');
    }
  } catch (err) {
    showNotification(`PiP error: ${err.message}`);
  }
}
video.addEventListener('enterpictureinpicture', () => pipBtn.classList.add('pip-active'));
video.addEventListener('leavepictureinpicture', () => pipBtn.classList.remove('pip-active'));

// Loop
loopBtn.addEventListener('click', () => {
  video.loop = !video.loop;
  loopBtn.classList.toggle('pip-active', video.loop);
  showNotification(video.loop ? 'Loop enabled' : 'Loop disabled');
});

// Screenshot
screenshotBtn.addEventListener('click', takeScreenshot);
function takeScreenshot() {
  const canvas = document.createElement('canvas');
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
  try {
    const dataURL = canvas.toDataURL('image/png');
    const a = document.createElement('a');
    const baseName = videoTitle.textContent.replace(/\.[^/.]+$/, '');
    a.href = dataURL;
    a.download = `${baseName}_screenshot.png`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showNotification('Screenshot taken');
  } catch (err) {
    showNotification(`Screenshot error`);
  }
}

// Jump buttons
jumpPrev.addEventListener('click', () => {
  video.currentTime = Math.max(0, video.currentTime - 10);
  showNotification('-10s');
});
jumpNext.addEventListener('click', () => {
  video.currentTime = Math.min(video.duration, video.currentTime + 10);
  showNotification('+10s');
});

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  if (['INPUT','TEXTAREA'].includes(e.target.tagName)) return;
  switch (e.key) {
    case ' ':
      e.preventDefault();
      togglePlayPause();
      break;
    case 'ArrowLeft':
      video.currentTime = Math.max(0, video.currentTime - 10);
      break;
    case 'ArrowRight':
      video.currentTime = Math.min(video.duration, video.currentTime + 10);
      break;
    case 'ArrowUp':
      video.volume = Math.min(1, video.volume + 0.1);
      volBar.value = video.volume;
      updateVolIcon();
      break;
    case 'ArrowDown':
      video.volume = Math.max(0, video.volume - 0.1);
      volBar.value = video.volume;
      updateVolIcon();
      break;
    case 'm':
    case 'M':
      video.muted = !video.muted;
      updateVolIcon();
      break;
    case 'f':
    case 'F':
      fullScreen.click();
      break;
    case 'p':
    case 'P':
      togglePictureInPicture();
      break;
    case 'c':
    case 'C':
      takeScreenshot();
      break;    case '?':
      helpBtn.click();
      break;
    case 's':
    case 'S':
      toggleSubtitles();
      break;
    case '0':
      video.currentTime = 0;
      break;
    case 's':
    case 'S':
      toggleSubtitles();
      break;
    default:
      if (!isNaN(e.key) && e.key >= '1' && e.key <= '9') {
        const percent = parseInt(e.key) * 10;
        video.currentTime = (video.duration * percent) / 100;
      }
  }
});

// Help toggle
helpBtn.addEventListener('click', () => {
  keyboardInfo.style.display = keyboardInfo.style.display === 'block' ? 'none' : 'block';
});
document.addEventListener('click', e => {
  if (keyboardInfo.style.display === 'block' && !keyboardInfo.contains(e.target) && e.target !== helpBtn) {
    keyboardInfo.style.display = 'none';
  }
});

// Subtitle functionality
let activeSubtitleTrack = null;

// Toggle subtitle menu
subtitleBtn.addEventListener('click', () => {
  subtitleMenu.style.display = subtitleMenu.style.display === 'block' ? 'none' : 'block';
});

// Close subtitle menu when clicking outside
document.addEventListener('click', e => {
  if (subtitleMenu.style.display === 'block' && 
      !subtitleMenu.contains(e.target) && 
      e.target !== subtitleBtn && 
      !e.target.closest('#subtitleBtn')) {
    subtitleMenu.style.display = 'none';
  }
});

// Handle subtitle selection
subtitleOptions.addEventListener('click', e => {
  if (e.target.classList.contains('subtitle-option')) {
    const value = e.target.getAttribute('data-value');
    document.querySelectorAll('.subtitle-option').forEach(opt => opt.classList.remove('active'));
    e.target.classList.add('active');
    
    // Disable all tracks first
    for (const track of video.textTracks) {
      track.mode = 'disabled';
    }
    
    // Enable selected track if not 'none'
    if (value !== 'none') {
      const selectedTrack = Array.from(video.textTracks).find(track => track.label === value);
      if (selectedTrack) {
        selectedTrack.mode = 'showing';
        activeSubtitleTrack = selectedTrack;
        showNotification(`Subtitles: ${value}`);
      }
    } else {
      activeSubtitleTrack = null;
      showNotification('Subtitles disabled');
    }
    
    // Save preference
    localStorage.setItem('mp4viewer_subtitle', value);
  }
});

// Handle subtitle file upload
subtitleFile.addEventListener('change', e => {
  const file = e.target.files[0];
  if (!file) return;
  
  // Create object URL for the subtitle file
  const subtitleUrl = URL.createObjectURL(file);
  const fileExt = file.name.split('.').pop().toLowerCase();
  const mimeType = fileExt === 'srt' ? 'application/x-subrip' : 'text/vtt';
  
  // Remove existing custom track if any
  for (let i = 0; i < video.textTracks.length; i++) {
    if (video.textTracks[i].label === 'Custom') {
      video.removeChild(video.querySelector(`track[label="Custom"]`));
      break;
    }
  }
  
  // Create and add the new track
  const track = document.createElement('track');
  track.kind = 'subtitles';
  track.label = 'Custom';
  track.srclang = 'en';
  track.src = subtitleUrl;
  
  video.appendChild(track);
  
  // Add option to menu and select it
  const customOption = document.querySelector('.subtitle-option[data-value="Custom"]');
  if (!customOption) {
    const newOption = document.createElement('div');
    newOption.className = 'subtitle-option';
    newOption.setAttribute('data-value', 'Custom');
    newOption.textContent = 'Custom';
    subtitleOptions.appendChild(newOption);
  }
  
  // Select the custom option
  document.querySelectorAll('.subtitle-option').forEach(opt => {
    opt.classList.remove('active');
    if (opt.getAttribute('data-value') === 'Custom') {
      opt.classList.add('active');
    }
  });
  
  // Enable the track
  setTimeout(() => {
    for (const track of video.textTracks) {
      if (track.label === 'Custom') {
        track.mode = 'showing';
        activeSubtitleTrack = track;
        break;
      }
    }
    showNotification('Custom subtitles loaded');
  }, 100);
  
  subtitleMenu.style.display = 'none';
});

// Check for existing video subtitles
video.addEventListener('loadedmetadata', () => {
  // Check if video has built-in subtitles
  if (video.textTracks && video.textTracks.length > 0) {
    // Clear existing options except 'none'
    Array.from(subtitleOptions.children).forEach(opt => {
      if (opt.getAttribute('data-value') !== 'none') {
        opt.remove();
      }
    });
    
    // Add options for each track
    for (const track of video.textTracks) {
      if (track.kind === 'subtitles' || track.kind === 'captions') {
        const option = document.createElement('div');
        option.className = 'subtitle-option';
        option.setAttribute('data-value', track.label);
        option.textContent = track.label || `${track.language} subtitles`;
        subtitleOptions.appendChild(option);
      }
    }
    
    // Check for saved preference
    const savedSubtitle = localStorage.getItem('mp4viewer_subtitle');
    if (savedSubtitle && savedSubtitle !== 'none') {
      for (const track of video.textTracks) {
        if (track.label === savedSubtitle) {
          track.mode = 'showing';
          activeSubtitleTrack = track;
          
          // Mark as active in the menu
          document.querySelectorAll('.subtitle-option').forEach(opt => {
            opt.classList.toggle('active', opt.getAttribute('data-value') === savedSubtitle);
          });
          
          break;
        }
      }
    } else {
      // Default to 'none'
      document.querySelector('.subtitle-option[data-value="none"]').classList.add('active');
    }
  }
});

// Toggle subtitles with S key
function toggleSubtitles() {
  if (!activeSubtitleTrack) {
    // If no active track, enable the first available
    for (const track of video.textTracks) {
      if (track.kind === 'subtitles' || track.kind === 'captions') {
        track.mode = 'showing';
        activeSubtitleTrack = track;
        showNotification(`Subtitles enabled: ${track.label || track.language}`);
        break;
      }
    }
  } else {
    // If active track, disable it
    activeSubtitleTrack.mode = 'disabled';
    activeSubtitleTrack = null;
    showNotification('Subtitles disabled');
  }
  
  // Update UI
  const activeValue = activeSubtitleTrack ? (activeSubtitleTrack.label || activeSubtitleTrack.language) : 'none';
  document.querySelectorAll('.subtitle-option').forEach(opt => {
    opt.classList.toggle('active', opt.getAttribute('data-value') === activeValue);
  });
  
  // Save preference
  localStorage.setItem('mp4viewer_subtitle', activeValue);
}

// Notification helper
function showNotification(msg) {
  notificationArea.textContent = msg;
  notificationArea.style.opacity = '1';
  setTimeout(() => { notificationArea.style.opacity = '0'; }, 2000);
}