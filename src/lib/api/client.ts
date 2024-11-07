import axios from "axios";

export const client = axios.create({
  //baseURL: "http://127.0.0.1:8000",
  baseURL: "https://api.seolleim.kr",
  headers: {
    "Content-Type": "application/json",
  },
  withCredentials: true,
});

client.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

const MAX_REFRESH_ATTEMPTS = 2;

// sessionStorage에서 시도 횟수를 관리하는 유틸리티 함수들
const getRefreshAttempts = (key: string): number => {
  const attempts = sessionStorage.getItem(`refresh_attempt_${key}`);
  return attempts ? parseInt(attempts, 10) : 0;
};

const incrementRefreshAttempts = (key: string): number => {
  const attempts = getRefreshAttempts(key) + 1;
  sessionStorage.setItem(`refresh_attempt_${key}`, attempts.toString());
  return attempts;
};

const clearRefreshAttempts = (key: string) => {
  sessionStorage.removeItem(`refresh_attempt_${key}`);
};

client.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const requestKey = `${originalRequest.method}-${originalRequest.url}`;

    if (error.response?.status === 401 && !originalRequest._retry) {
      const attempts = getRefreshAttempts(requestKey);

      if (attempts >= MAX_REFRESH_ATTEMPTS) {
        console.log("Token refresh max attempts exceeded");
        localStorage.removeItem("access_token");
        // 모든 refresh attempt 기록 초기화
        Object.keys(sessionStorage)
          .filter((key) => key.startsWith("refresh_attempt_"))
          .forEach((key) => sessionStorage.removeItem(key));
        window.location.href = "/login";
        return Promise.reject(error);
      }

      try {
        originalRequest._retry = true;
        incrementRefreshAttempts(requestKey);

        const response = await client.post("/api/token/refresh/");
        const { access } = response.data;

        if (access) {
          localStorage.setItem("access_token", access);
          originalRequest.headers.Authorization = `Bearer ${access}`;
          clearRefreshAttempts(requestKey); // 성공 시 해당 요청의 시도 횟수 초기화
          return client(originalRequest);
        }
      } catch (refreshError) {
        console.log("Token refresh failed:", refreshError);
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

// 30분마다 모든 refresh attempt 기록 초기화
setInterval(() => {
  Object.keys(sessionStorage)
    .filter((key) => key.startsWith("refresh_attempt_"))
    .forEach((key) => sessionStorage.removeItem(key));
}, 30 * 60 * 1000);
