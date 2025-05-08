        const token = localStorage.getItem('jwtToken');
        if (!token) {
            window.location.href = '/index.html';
        }

        const createGroupForm = document.getElementById('createGroupForm');
        const groupsList = document.getElementById('groupsList');
        const groupModal = document.getElementById('groupModal');
        const modalGroupName = document.getElementById('modalGroupName');
        const membersList = document.getElementById('membersList');
        const folderSelect = document.getElementById('folderSelect');
        const addFolderBtn = document.getElementById('addFolderBtn');
        const folderPermissions = document.getElementById('folderPermissions');
        const loading = document.querySelector('.loading');
        const closeModalBtn = document.getElementById('closeModalBtn');

        let currentGroupId = null;
        let currentGroupName = null;

        function showLoading() {
            loading.style.display = 'flex';
        }

        function hideLoading() {
            loading.style.display = 'none';
        }

        createGroupForm.onsubmit = async (e) => {
            e.preventDefault();
            showLoading();

            const groupName = document.getElementById('groupName').value;
            const memberUsernames = document.getElementById('memberUsernames').value
                .split('\n')
                .map(username => username.trim())
                .filter(username => username);

            if (memberUsernames.length < 2) {
                showNotification('Please enter at least 2 usernames', 'is-warning');
                hideLoading();
                return;
            }

            try {
                const res = await fetch('/api/groups/create', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({
                        groupName,
                        memberUsernames: memberUsernames 
                    })
                });

                if (!res.ok) {
                    const errorText = await res.text();
                    throw new Error(errorText);
                }

                const data = await res.json();
                showNotification('Group created successfully!', 'is-success');
                createGroupForm.reset();
                loadGroups();
            } catch (err) {
                showNotification(err.message, 'is-danger');
            } finally {
                hideLoading();
            }
        };

        async function loadGroups() {
            showLoading();
            try {
                const res = await fetch('/api/show-group-I-created', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const groups = await res.json();

                if (groups.length === 0) {
                    groupsList.innerHTML = `
                        <div class="empty-state">
                            <i class="fas fa-users-slash"></i>
                            <p>You haven't created any groups yet.</p>
                            <p class="mt-2">Create a new group to start sharing your folders with others.</p>
                        </div>
                    `;
                } else {
                    groupsList.innerHTML = groups.map(group => {
                        const memberCount = group.members.length;
                        
                        return `
                            <div class="card group-card mb-4">
                                <header class="card-header">
                                    <p class="card-header-title">
                                        <span class="icon mr-2">
                                            <i class="fas fa-users"></i>
                                        </span>
                                        ${group.groupName}
                                    </p>
                                </header>
                                <div class="card-content">
                                    <div class="content">
                                        <div class="group-members-preview">
                                            ${group.members.slice(0, 5).map(member => `
                                                <span class="tag is-info member-tag">
                                                    <span class="icon is-small mr-1">
                                                        <i class="fas fa-user"></i>
                                                    </span>
                                                    ${member.username}
                                                </span>
                                            `).join('')}
                                            ${memberCount > 5 ? `
                                                <span class="tag is-info member-tag">
                                                    +${memberCount - 5} more
                                                </span>
                                            ` : ''}
                                        </div>
                                        
                                        <div class="group-stats">
                                            <div class="group-stat">
                                                <strong>${memberCount}</strong>
                                                Members
                                            </div>
                                            <div class="group-stat">
                                                <strong id="folderCount-${group.groupId}">-</strong>
                                                Folders
                                            </div>
                                        </div>
                                        
                                        <button class="button is-primary is-fullwidth mt-4" 
                                                onclick="openGroupDetails('${group.groupId}', '${group.groupName}')">
                                            <span class="icon">
                                                <i class="fas fa-cog"></i>
                                            </span>
                                            <span>Manage Group</span>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        `;
                    }).join('');
                    
                    groups.forEach(group => {
                        fetchFolderCount(group.groupId);
                    });
                }
            } catch (err) {
                showNotification('Failed to load groups', 'is-danger');
                groupsList.innerHTML = `
                    <div class="notification is-warning">
                        <p>Could not load your groups. Please try again later.</p>
                    </div>
                `;
            } finally {
                hideLoading();
            }
        }
        
        async function fetchFolderCount(groupId) {
            try {
                const permsRes = await fetch(`/api/show-groups-permissions?groupId=${groupId}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const permsData = await permsRes.json();
                
                const folderCount = Object.keys(permsData.permissions).length;
                const countElement = document.getElementById(`folderCount-${groupId}`);
                if (countElement) {
                    countElement.textContent = folderCount;
                }
            } catch (err) {
                console.error(`Failed to load folder count for group ${groupId}`, err);
            }
        }

        async function openGroupDetails(groupId, groupName) {
            currentGroupId = groupId;
            currentGroupName = groupName;
            modalGroupName.textContent = groupName;
            showLoading();

            try {
                // Load group members
                const membersRes = await fetch(`/api/groups/members/${groupId}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const membersData = await membersRes.json();
                
                if (membersData.members.length === 0) {
                    membersList.innerHTML = `
                        <div class="empty-state">
                            <i class="fas fa-user-slash"></i>
                            <p>This group has no members.</p>
                        </div>
                    `;
                } else {
                    membersList.innerHTML = membersData.members.map(member => `
                        <div class="box">
                            <div class="level">
                                <div class="level-left">
                                    <div class="level-item">
                                        <span class="icon mr-2 has-text-info">
                                            <i class="fas fa-user-circle"></i>
                                        </span>
                                        <span>${member.username}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `).join('');
                }

                const permsRes = await fetch(`/api/show-groups-permissions?groupId=${groupId}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const permsData = await permsRes.json();
                
                const foldersRes = await fetch('/api/my-folders', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const folders = await foldersRes.json();

                if (folders.length === 0) {
                    folderPermissions.innerHTML = `
                        <div class="empty-state">
                            <i class="fas fa-folder-open"></i>
                            <p>You don't have any folders to share.</p>
                            <p class="mt-2">Create a folder first to share with this group.</p>
                        </div>
                    `;
                } else {
                    folderPermissions.innerHTML = await Promise.all(folders.map(async (folder) => {
                        const currentPermsRes = await fetch(`/api/groups/view-current-permissions/${groupId}/${folder.folderId}`, {
                            headers: { 'Authorization': `Bearer ${token}` }
                        });
                        const currentPerms = await currentPermsRes.json();
                        
                        return `
                            <div class="box folder-permission">
                                <div class="level">
                                    <div class="level-left">
                                        <div class="level-item">
                                            <span class="icon mr-2 has-text-primary">
                                                <i class="fas fa-folder"></i>
                                            </span>
                                            <span>${folder.folderName}</span>
                                        </div>
                                    </div>
                                    <div class="level-right">
                                        <div class="level-item">
                                            <div class="field is-grouped">
                                                <label class="checkbox mr-4">
                                                    <input type="checkbox" 
                                                           ${currentPerms.permissions.view ? 'checked' : ''}
                                                           onchange="updateFolderPermission('${folder.folderId}', 'view', this.checked)">
                                                    <span class="icon-text">
                                                        <span class="icon is-small has-text-info">
                                                            <i class="fas fa-eye"></i>
                                                        </span>
                                                        <span>View</span>
                                                    </span>
                                                </label>
                                                <label class="checkbox mr-4">
                                                    <input type="checkbox"
                                                           ${currentPerms.permissions.download ? 'checked' : ''}
                                                           onchange="updateFolderPermission('${folder.folderId}', 'download', this.checked)">
                                                    <span class="icon-text">
                                                        <span class="icon is-small has-text-success">
                                                            <i class="fas fa-download"></i>
                                                        </span>
                                                        <span>Download</span>
                                                    </span>
                                                </label>
                                                <label class="checkbox mr-4">
                                                    <input type="checkbox"
                                                           ${currentPerms.permissions.upload ? 'checked' : ''}
                                                           onchange="updateFolderPermission('${folder.folderId}', 'upload', this.checked)">
                                                    <span class="icon-text">
                                                        <span class="icon is-small has-text-warning">
                                                            <i class="fas fa-upload"></i>
                                                        </span>
                                                        <span>Upload</span>
                                                    </span>
                                                </label>
                                                <label class="checkbox">
                                                    <input type="checkbox"
                                                           ${currentPerms.permissions.delete ? 'checked' : ''}
                                                           onchange="updateFolderPermission('${folder.folderId}', 'delete', this.checked)">
                                                    <span class="icon-text">
                                                        <span class="icon is-small has-text-danger">
                                                            <i class="fas fa-trash"></i>
                                                        </span>
                                                        <span>Delete</span>
                                                    </span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `;
                    })).then(html => html.join(''));
                }

                if (folders.length === 0) {
                    folderSelect.innerHTML = `<option value="">No folders available</option>`;
                    addFolderBtn.disabled = true;
                } else {
                    // Get folders that don't have permissions yet
                    const foldersWithPermissions = await Promise.all(folders.map(async (folder) => {
                        const currentPermsRes = await fetch(`/api/groups/view-current-permissions/${groupId}/${folder.folderId}`, {
                            headers: { 'Authorization': `Bearer ${token}` }
                        });
                        const currentPerms = await currentPermsRes.json();
                        return {
                            ...folder,
                            hasPermissions: Object.values(currentPerms.permissions).some(v => v === true)
                        };
                    }));

                    const availableFolders = foldersWithPermissions.filter(f => !f.hasPermissions);

                    if (availableFolders.length === 0) {
                        folderSelect.innerHTML = `<option value="">All folders have permissions</option>`;
                        addFolderBtn.disabled = true;
                    } else {
                        folderSelect.innerHTML = `
                            <option value="">Select a folder</option>
                            ${availableFolders.map(folder => `
                                <option value="${folder.folderId}">${folder.folderName}</option>
                            `).join('')}
                        `;
                        addFolderBtn.disabled = false;
                    }
                }

                document.querySelectorAll('.tabs li').forEach((li, index) => {
                    if (index === 0) {
                        li.classList.add('is-active');
                    } else {
                        li.classList.remove('is-active');
                    }
                });
                
                document.querySelectorAll('.tab-content').forEach((content, index) => {
                    content.style.display = index === 0 ? 'block' : 'none';
                });

                groupModal.classList.add('is-active');
            } catch (err) {
                showNotification('Failed to load group details', 'is-danger');
            } finally {
                hideLoading();
            }
        }

        addFolderBtn.onclick = async () => {
            const folderId = folderSelect.value;
            if (!folderId) {
                showNotification('Please select a folder', 'is-warning');
                return;
            }

            showLoading();
            try {
                const res = await fetch(`/api/folders/${folderId}/groups/${currentGroupId}/permissions`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({
                        view: true,
                        download: false
                    })
                });

                if (!res.ok) {
                    throw new Error(await res.text());
                }

                showNotification('Folder permission added successfully', 'is-success');
                openGroupDetails(currentGroupId, currentGroupName);
            } catch (err) {
                showNotification(err.message, 'is-danger');
            } finally {
                hideLoading();
            }
        };

        async function updateFolderPermission(folderId, permission, value) {
            showLoading();
            try {
                const res = await fetch(`/api/folders/${folderId}/groups/${currentGroupId}/permissions`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({
                        [permission]: value
                    })
                });

                if (!res.ok) {
                    throw new Error(await res.text());
                }

                showNotification('Permission updated successfully', 'is-success');
            } catch (err) {
                showNotification(err.message, 'is-danger');
                openGroupDetails(currentGroupId, currentGroupName); 
            } finally {
                hideLoading();
            }
        }

        document.querySelectorAll('.tabs a').forEach(tab => {
            tab.onclick = (e) => {
                e.preventDefault();
                const tabName = e.target.closest('a').dataset.tab;
                
                document.querySelectorAll('.tabs li').forEach(li => li.classList.remove('is-active'));
                e.target.closest('li').classList.add('is-active');
                
                document.querySelectorAll('.tab-content').forEach(content => {
                    content.style.display = 'none';
                });
                document.getElementById(`${tabName}Tab`).style.display = 'block';
            };
        });

        // Close modal
        document.querySelectorAll('.modal .delete, .modal-background, #closeModalBtn').forEach(el => {
            el.onclick = () => {
                groupModal.classList.remove('is-active');
                loadGroups(); 
            };
        });

        function showNotification(message, type = 'is-info') {
            document.querySelectorAll('.notification').forEach(note => note.remove());
            
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.innerHTML = `
                <button class="delete"></button>
                <span class="icon-text">
                    <span class="icon">
                        <i class="fas ${type === 'is-danger' ? 'fa-exclamation-circle' : 
                                       type === 'is-warning' ? 'fa-exclamation-triangle' : 
                                       type === 'is-success' ? 'fa-check-circle' : 'fa-info-circle'}"></i>
                    </span>
                    <span>${message}</span>
                </span>
            `;
            document.body.appendChild(notification);

            setTimeout(() => {
                notification.remove();
            }, 5000);

            notification.querySelector('.delete').onclick = () => {
                notification.remove();
            };
        }

        document.getElementById('logoutBtn').onclick = () => {
            localStorage.removeItem('jwtToken');
            window.location.href = '/index.html';
        };

        loadGroups();
