        // Tab switching functionality
        document.addEventListener('DOMContentLoaded', () => {
            const tabs = document.querySelectorAll('.tabs li');
            const tabContents = document.querySelectorAll('.tab-content');
            
            tabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    tabs.forEach(t => t.classList.remove('is-active'));
                    tab.classList.add('is-active');
                    
                    const tabId = tab.getAttribute('data-tab');
                    tabContents.forEach(content => {
                        content.classList.remove('is-active');
                        if (content.id === tabId) {
                            content.classList.add('is-active');
                        }
                    });
                });
            });

            // Mobile navbar toggle
            const navbarBurger = document.querySelector('.navbar-burger');
            const navbarMenu = document.querySelector('.navbar-menu');
            
            if (navbarBurger && navbarMenu) {
                navbarBurger.addEventListener('click', () => {
                    navbarBurger.classList.toggle('is-active');
                    navbarMenu.classList.toggle('is-active');
                });
            }
            
            // Load data immediately
            loadAllData();
            
            // Set up refresh button
            const refreshButton = document.getElementById('refreshButton');
            if (refreshButton) {
                refreshButton.addEventListener('click', loadAllData);
            }
        });
        
        // Utility function to format bytes to human-readable format
        function formatBytes(bytes, decimals = 2) {
            if (bytes === 0) return '0 Bytes';
            
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
            
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        }
        
        // Function to fetch data from all endpoints and update UI
        async function loadAllData() {
            try {
                // Get JWT token from localStorage
                const token = localStorage.getItem('jwtToken');
                if (!token) {
                    alert('Authentication token not found. Please log in first.');
                    return;
                }
                
                const endpoints = [
                    '/api/staff/stats/total-users',
                    '/api/staff/stats/total-folders',
                    '/api/staff/stats/total-public-folders',
                    '/api/staff/stats/total-private-folders',
                    '/api/staff/stats/total-files',
                    '/api/staff/stats/total-storage-used',
                    '/api/staff/stats/average-files-per-folder',
                    '/api/staff/stats/top-users-by-folders',
                    '/api/staff/stats/top-users-by-files',
                    '/api/staff/stats/recent-uploads'
                ];
                
                // Fetch all data in parallel with Authorization header
                const responses = await Promise.all(endpoints.map(async (endpoint, index) => {
                    try {
                        const res = await fetch(endpoint, {
                            headers: {
                                'Authorization': `Bearer ${token}`
                            }
                        });
                        
                        if (!res.ok) {
                            const errorText = await res.text();
                            console.error(`Error fetching ${endpoint}:`, {
                                status: res.status,
                                statusText: res.statusText,
                                error: errorText
                            });
                            throw new Error(`Error fetching ${endpoint}: ${res.status} - ${errorText}`);
                        }
                        
                        return await res.json();
                    } catch (err) {
                        console.error(`Failed to fetch ${endpoint}:`, err);
                        return null;
                    }
                }));
                
                // Update timestamp
                const lastUpdatedElement = document.getElementById('lastUpdated');
                if (lastUpdatedElement) {
                    lastUpdatedElement.textContent = new Date().toLocaleString();
                }
                
                // Process responses
                const [
                    totalUsersData,
                    totalFoldersData,
                    totalPublicFoldersData,
                    totalPrivateFoldersData,
                    totalFilesData,
                    totalStorageData,
                    avgFilesPerFolderData,
                    topUsersByFoldersData,
                    topUsersByFilesData,
                    recentUploadsData
                ] = responses;
                
                // Log which endpoints failed
                const failedEndpoints = endpoints.filter((_, index) => responses[index] === null);
                if (failedEndpoints.length > 0) {
                    console.warn('The following endpoints failed to load:', failedEndpoints);
                }
                
                // Update UI with data
                updateUIWithData({
                    totalUsersData,
                    totalFoldersData,
                    totalPublicFoldersData,
                    totalPrivateFoldersData,
                    totalFilesData,
                    totalStorageData,
                    avgFilesPerFolderData,
                    topUsersByFoldersData,
                    topUsersByFilesData,
                    recentUploadsData
                });
                
            } catch (error) {
                console.error('Error loading dashboard data:', error);
                console.error('Error details:', {
                    message: error.message,
                    stack: error.stack
                });
                alert('Failed to load dashboard data. Please check the console for more details.');
            }
        }
        
        // Function to update UI elements with fetched data
        function updateUIWithData(data) {
            // Basic stats
            if (data.totalUsersData) {
                const element = document.getElementById('totalUsers');
                if (element) {
                    element.textContent = data.totalUsersData.totalUsers.toLocaleString();
                }
            }
            
            if (data.totalFoldersData) {
                const element = document.getElementById('totalFolders');
                if (element) {
                    element.textContent = data.totalFoldersData.totalFolders.toLocaleString();
                }
            }
            
            if (data.totalFilesData) {
                const element = document.getElementById('totalFiles');
                if (element) {
                    element.textContent = data.totalFilesData.totalFiles.toLocaleString();
                }
            }
            
            if (data.totalStorageData) {
                const bytes = data.totalStorageData.totalStorage;
                const totalStorageElement = document.getElementById('totalStorage');
                const storageSizeFormattedElement = document.getElementById('storageSizeFormatted');
                const avgFileSizeElement = document.getElementById('avgFileSize');
                
                if (totalStorageElement) {
                    totalStorageElement.textContent = formatBytes(bytes);
                }
                if (storageSizeFormattedElement) {
                    storageSizeFormattedElement.textContent = formatBytes(bytes);
                }
                
                // Calculate average file size if we have both stats
                if (avgFileSizeElement) {
                    if (data.totalFilesData && data.totalFilesData.totalFiles > 0) {
                        const avgSize = bytes / data.totalFilesData.totalFiles;
                        avgFileSizeElement.textContent = formatBytes(avgSize);
                    } else {
                        avgFileSizeElement.textContent = 'N/A';
                    }
                }
            }
            
            // Folder distribution
            if (data.totalPublicFoldersData && data.totalPrivateFoldersData) {
                const publicFolders = data.totalPublicFoldersData.totalPublicFolders;
                const privateFolders = data.totalPrivateFoldersData.totalPrivateFolders;
                
                const totalPublicFoldersElement = document.getElementById('totalPublicFolders');
                const totalPrivateFoldersElement = document.getElementById('totalPrivateFolders');
                const folderProgressBarElement = document.getElementById('folderProgressBar');
                const folderDistributionTextElement = document.getElementById('folderDistributionText');
                
                if (totalPublicFoldersElement) {
                    totalPublicFoldersElement.textContent = publicFolders.toLocaleString();
                }
                if (totalPrivateFoldersElement) {
                    totalPrivateFoldersElement.textContent = privateFolders.toLocaleString();
                }
                
                // Update progress bar
                const total = publicFolders + privateFolders;
                if (total > 0) {
                    const publicPercentage = (publicFolders / total) * 100;
                    if (folderProgressBarElement) {
                        folderProgressBarElement.value = publicPercentage;
                    }
                    if (folderDistributionTextElement) {
                        folderDistributionTextElement.textContent = 
                            `${publicPercentage.toFixed(1)}% Public / ${(100 - publicPercentage).toFixed(1)}% Private`;
                    }
                } else {
                    if (folderProgressBarElement) {
                        folderProgressBarElement.value = 0;
                    }
                    if (folderDistributionTextElement) {
                        folderDistributionTextElement.textContent = 'No folders available';
                    }
                }
            }
            
            // Average files per folder
            if (data.avgFilesPerFolderData) {
                const element = document.getElementById('averageFilesPerFolder');
                if (element) {
                    element.textContent = data.avgFilesPerFolderData.averageFilesPerFolder.toFixed(1);
                }
            }
            
            // Recent uploads
            if (data.recentUploadsData) {
                const element = document.getElementById('recentUploads');
                if (element) {
                    element.textContent = data.recentUploadsData.recentUploads.toLocaleString();
                }
            }
            
            // Top users by folders
            if (data.topUsersByFoldersData && data.topUsersByFoldersData.topUsersByFolders) {
                const container = document.getElementById('topUsersByFolders');
                if (container) {
                    container.innerHTML = '';
                    
                    const users = data.topUsersByFoldersData.topUsersByFolders;
                    if (users.length === 0) {
                        container.innerHTML = '<p class="has-text-centered">No user data available</p>';
                    } else {
                        users.forEach((user, index) => {
                            const userItem = document.createElement('div');
                            userItem.className = 'user-list-item';
                            userItem.innerHTML = `
                                <div>
                                    <span class="icon-text">
                                        <span class="icon has-text-info">
                                            <i class="fas fa-user-circle"></i>
                                        </span>
                                        <span class="has-text-weight-medium">${user.username}</span>
                                    </span>
                                </div>
                                <div>
                                    <span class="tag is-primary is-medium">${user.folderCount} folders</span>
                                </div>
                            `;
                            container.appendChild(userItem);
                        });
                    }
                }
            }
            
            // Top users by files
            if (data.topUsersByFilesData && data.topUsersByFilesData.topUsersByFiles) {
                const container = document.getElementById('topUsersByFiles');
                if (container) {
                    container.innerHTML = '';
                    
                    const users = data.topUsersByFilesData.topUsersByFiles;
                    if (users.length === 0) {
                        container.innerHTML = '<p class="has-text-centered">No user data available</p>';
                    } else {
                        users.forEach((user, index) => {
                            const userItem = document.createElement('div');
                            userItem.className = 'user-list-item';
                            userItem.innerHTML = `
                                <div>
                                    <span class="icon-text">
                                        <span class="icon has-text-info">
                                            <i class="fas fa-user-circle"></i>
                                        </span>
                                        <span class="has-text-weight-medium">${user.username}</span>
                                    </span>
                                </div>
                                <div>
                                    <span class="tag is-success is-medium">${user.fileCount} files</span>
                                </div>
                            `;
                            container.appendChild(userItem);
                        });
                    }
                }
            }
        }