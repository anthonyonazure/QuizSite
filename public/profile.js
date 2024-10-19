// Define a debug mode flag (you can set this to false in production)
const DEBUG_MODE = true;

function secureLog(message, data) {
    if (DEBUG_MODE) {
        if (data) {
            console.log(message, data);
        } else {
            console.log(message);
        }
    }
}

function secureError(message, error) {
    if (DEBUG_MODE) {
        console.error(message, error);
    }
}

secureLog('profile.js loaded');

async function fetchProfileData() {
    try {
        secureLog('Fetching profile data...');
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

        const response = await fetch('/api/profile', {
            method: 'GET',
            credentials: 'include',
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            const errorData = await response.json();
            secureError('Error response:', errorData);
            throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.message || 'Unknown error'}`);
        }
        const data = await response.json();
        secureLog('Profile data received:', data);
        return data;
    } catch (error) {
        if (error.name === 'AbortError') {
            secureError('Request timed out');
        } else {
            secureError('Error fetching profile data:', error);
        }
        throw error; // Re-throw the error to be caught in initializeProfile
    }
}

function calculateCompletedQuizzes(totalQuestions) {
    const questionsPerQuiz = 10;
    return Math.floor(totalQuestions / questionsPerQuiz);
}

function getTrendText(trend) {
    if (trend > 0) return `↑ Improving (${trend.toFixed(2)}%)`;
    if (trend < 0) return `↓ Declining (${Math.abs(trend).toFixed(2)}%)`;
    return "→ Stable";
}

function displayProfileData(profileData) {
    secureLog('Displaying profile data:', profileData);
    const profileInfoElement = document.getElementById('profile-info');
    if (profileData) {
        profileInfoElement.innerHTML = `
            <p><strong>Email:</strong> <span id="user-email">${profileData.email || 'N/A'}</span></p>
            <p><strong>Reddit Handle:</strong> <span id="user-reddit-handle">${profileData.redditHandle || 'N/A'}</span></p>
            <p><strong>Total Questions Answered:</strong> <span id="user-total-questions">${profileData.totalQuestions || '0'}</span></p>
            <p><strong>Correct Answers:</strong> <span id="user-correct-answers">${profileData.totalCorrect || '0'}</span></p>
            <p><strong>Completed Quizzes:</strong> <span id="user-completed-quizzes">${calculateCompletedQuizzes(profileData.totalQuestions || 0)}</span></p>
            <p><strong>Overall Percent Correct:</strong> <span id="user-percent-correct">${profileData.percentCorrect ? `${profileData.percentCorrect.toFixed(2)}%` : 'N/A'}</span></p>
            <p><strong>Percent Correct Trend:</strong> <span id="user-percent-trend">${getTrendText(profileData.percentCorrectTrend || 0)}</span></p>
            <p><strong>Overall Rank:</strong> <span id="user-overall-rank">${profileData.rank || 'N/A'}</span></p>
        `;
    } else {
        profileInfoElement.innerHTML = '<p>Error loading profile information. Please try again later.</p>';
    }
    secureLog('Profile data displayed');
}

async function initializeProfile() {
    secureLog('Initializing profile...');
    const profileInfoElement = document.getElementById('profile-info');
    profileInfoElement.innerHTML = '<p id="loading-message">Loading profile data...</p>';

    try {
        const profileData = await fetchProfileData();
        if (profileData) {
            secureLog('Profile data fetched successfully');
            displayProfileData(profileData);
        } else {
            throw new Error('Profile data is null or undefined');
        }
    } catch (error) {
        secureError('Failed to fetch profile data:', error);
        profileInfoElement.innerHTML = `<p>Failed to load profile data. Error: ${error.message}</p>`;
    }
}

document.addEventListener('DOMContentLoaded', initializeProfile);
secureLog('Event listener added for DOMContentLoaded');
