document.addEventListener('DOMContentLoaded', () => {
    initializeAuth();
    initializeUI();
    loadStats();
    loadGroups();
});

const token = localStorage.getItem('jwtToken');
let currentGroupId = null;

function initializeAuth() {
    if (!token) {
        window.location.href = '/index.html';
    }
}

function initializeUI() {
    setupModalControls();
    setupTabSwitching();
}

function setupModalControls() {
    const modalCloseButtons = document.querySelectorAll('#closeModalBtn, .modal .delete');
    modalCloseButtons.forEach(button => {
        button.addEventListener('click', () => toggleModal(false));
    });
}

function setupTabSwitching() {
    document.querySelectorAll('.tabs a').forEach(tab => {
        tab.addEventListener('click', (e) => {
            e.preventDefault();
            const target = e.target.getAttribute('data-tab');
            document.querySelectorAll('.tabs li').forEach(li => li.classList.remove('is-active'));
            e.target.parentElement.classList.add('is-active');
            document.querySelectorAll('.tab-content').forEach(content => content.style.display = 'none');
            document.getElementById(target + 'Tab').style.display = 'block';
        });
    });
}

async function loadStats() {
    try {
        const stats = await fetchData('/api/staff/groups/stats');
        updateStatsDisplay(stats);
    } catch (err) {
        console.error('Failed to load stats:', err);
    }
}

function updateStatsDisplay(stats) {
    document.getElementById('totalGroups').textContent = stats.totalGroups || '-';
    document.getElementById('totalMembers').textContent = stats.totalMembers || '-';
    document.getElementById('flaggedGroups').textContent = stats.flaggedGroups || '-';
    document.getElementById('pendingInvites').textContent = stats.totalPendingInvites || '-';
}

async function loadGroups() {
    showLoading();
    try {
        const { groups } = await fetchData('/api/staff/groups');
        renderGroupsList(groups);
    } catch (err) {
        console.error('Failed to load groups:', err);
        displayError('Failed to load groups. Please try again later.');
    } finally {
        hideLoading();
    }
}

function renderGroupsList(groups) {
    const groupsList = document.getElementById('groupsList');
    if (!groups.length) {
        groupsList.innerHTML = `<div class="notification is-info"><p>No groups found in the system.</p></div>`;
        return;
    }
    groupsList.innerHTML = groups.map(group => createGroupCard(group)).join('');
}

function createGroupCard(group) {
    return `
        <div class="card group-card ${group.flagged ? 'flagged' : ''}">
            <div class="card-content">
                <div class="flex justify-between items-center">
                    <div>
                        <p class="text-lg font-bold">${group.groupName}</p>
                        <p class="text-sm text-gray-500">Owner: ${group.owner}</p>
                    </div>
                    <div class="flex space-x-2">
                        <span class="tag">${group.memberCount} members</span>
                        <span class="tag">${group.pendingInviteCount} pending</span>
                        <span class="tag">${group.folderCount} folders</span>
                    </div>
                </div>
                <div class="mt-4">
                    <button class="button is-primary is-fullwidth" 
                            onclick="openGroupDetails('${group.groupId}', '${group.groupName}')">
                        Manage Group
                    </button>
                </div>
            </div>
        </div>
    `;
}

async function openGroupDetails(groupId, groupName) {
    currentGroupId = groupId;
    document.getElementById('modalGroupName').textContent = groupName;
    toggleModal(true);
    showLoading();
    
    try {
        const membersData = await fetchData(`/api/groups/members/${groupId}`);
        renderMembersList(membersData.members);
        const activityData = await fetchData(`/api/staff/groups/${groupId}/activity`);
        renderActivityList(activityData.activities);
    } catch (err) {
        console.error('Error loading group details:', err);
    } finally {
        hideLoading();
    }
}

function renderMembersList(members) {
    document.getElementById('membersList').innerHTML = members.map(member => `
        <div class="flex justify-between items-center p-2 border-b">
            <span>${member.username}</span>
            <button class="text-red-500" onclick="removeMember('${currentGroupId}', '${member.username}')">
                <i class="fas fa-user-minus"></i>
            </button>
        </div>
    `).join('');
}

function renderActivityList(activities) {
    document.getElementById('activityList').innerHTML = activities.map(activity => `
        <div class="p-2">
            <p>${activity.activity}</p>
            <small>${new Date(activity.timestamp).toLocaleString()}</small>
        </div>
    `).join('');
}

async function removeMember(groupId, username) {
    if (!confirm(`Are you sure you want to remove ${username} from this group?`)) return;

    try {
        await fetchData(`/api/staff/groups/${groupId}/members/${username}`, 'DELETE');
        openGroupDetails(groupId, document.getElementById('modalGroupName').textContent);
    } catch (err) {
        console.error('Failed to remove member:', err);
        alert('Failed to remove member: ' + err.message);
    }
}

async function flagGroup() {
    const reason = prompt('Please enter the reason for flagging this group:');
    if (!reason) return;

    try {
        await fetchData(`/api/staff/groups/${currentGroupId}/flag`, 'POST', { reason });
        alert('Group flagged successfully');
        loadGroups();
    } catch (err) {
        console.error('Failed to flag group:', err);
        alert('Failed to flag group: ' + err.message);
    }
}

async function fetchData(url, method = 'GET', body = null) {
    const response = await fetch(url, {
        method,
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: body ? JSON.stringify(body) : null
    });
    if (!response.ok) throw new Error(await response.text());
    return await response.json();
}

function toggleModal(show) {
    document.getElementById('groupModal').classList.toggle('hidden', !show);
}

function showLoading() {
    document.querySelector('.loading')?.classList.remove('hidden');
}

function hideLoading() {
    document.querySelector('.loading')?.classList.add('hidden');
}

function displayError(message) {
    document.getElementById('groupsList').innerHTML = `
        <div class="notification is-danger">${message}</div>
    `;
}
