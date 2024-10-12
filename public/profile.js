async function fetchProfileData() {
    try {
        console.log('Fetching profile data...');
        const response = await fetch('/api/profile', {
            method: 'GET',
            credentials: 'include'
        });
        if (!response.ok) {
            const errorData = await response.json();
            console.error('Error response:', errorData);
            throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.message || 'Unknown error'}`);
        }
        const data = await response.json();
        console.log('Profile data received:', data);
        return data;
    } catch (error) {
        console.error('Error fetching profile data:', error);
        throw error; // Re-throw the error to be caught in initializeProfile
    }
}

function calculateCompletedQuizzes(totalQuestions) {
    const questionsPerQuiz = 12;
    return Math.floor(totalQuestions / questionsPerQuiz);
}

function getTrendText(trend) {
    if (trend > 0) return `↑ Improving (${trend.toFixed(2)}%)`;
    if (trend < 0) return `↓ Declining (${Math.abs(trend).toFixed(2)}%)`;
    return "→ Stable";
}

function displayProfileData(profileData) {
    const profileInfoElement = document.getElementById('profile-info');
    if (profileData) {
        profileInfoElement.innerHTML = `
            <p><strong>Email:</strong> <span id="user-email">${profileData.email || 'N/A'}</span></p>
            <p><strong>Reddit Handle:</strong> <span id="user-reddit-handle">${profileData.redditHandle || 'N/A'}</span></p>
            <p><strong>Correct Answers:</strong> <span id="user-correct-answers">${profileData.totalCorrect || '0'}</span></p>
            <p><strong>Completed Quizzes:</strong> <span id="user-completed-quizzes">${calculateCompletedQuizzes(profileData.totalQuestions || 0)}</span></p>
            <p><strong>Overall Percent Correct:</strong> <span id="user-percent-correct">${profileData.percentCorrect ? `${profileData.percentCorrect.toFixed(2)}%` : 'N/A'}</span></p>
            <p><strong>Percent Correct Trend:</strong> <span id="user-percent-trend">${getTrendText(profileData.percentCorrectTrend || 0)}</span></p>
            <p><strong>Overall Rank:</strong> <span id="user-overall-rank">${profileData.rank || 'N/A'}</span></p>
            <p><strong>Rank (Similar Questions Answered):</strong> <span id="user-similar-rank">${profileData.similarQuestionsRank || 'N/A'}</span></p>
        `;
    } else {
        profileInfoElement.innerHTML = '<p>Error loading profile information. Please try again later.</p>';
    }
}

async function initializeProfile() {
    console.log('Initializing profile...');
    const profileInfoElement = document.getElementById('profile-info');
    profileInfoElement.innerHTML = '<p id="loading-message">Loading profile data...</p>';

    try {
        const profileData = await fetchProfileData();
        if (profileData) {
            console.log('Displaying profile data...');
            displayProfileData(profileData);
        } else {
            throw new Error('Profile data is null or undefined');
        }
    } catch (error) {
        console.error('Failed to fetch profile data:', error);
        profileInfoElement.innerHTML = `<p>Failed to load profile data. Error: ${error.message}</p>`;
    }
}

document.addEventListener('DOMContentLoaded', initializeProfile);
