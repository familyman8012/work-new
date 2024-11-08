import axios from "axios";

export const client = axios.create({
  baseURL: "https://api.seolleim.kr",
  headers: {
    "Content-Type": "application/json",
  },
  withCredentials: true, // 쿠키 전송 허용
});

// 요청 인터셉터: access_token을 Authorization 헤더에 추가
client.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

const MAX_REFRESH_ATTEMPTS = 2;

// sessionStorage에서 시도 횟수 관리
const getRefreshAttempts = (key: string) => {
  const attempts = sessionStorage.getItem(`refresh_attempt_${key}`);
  return attempts ? parseInt(attempts, 10) : 0;
};

const incrementRefreshAttempts = (key: string) => {
  const attempts = getRefreshAttempts(key) + 1;
  sessionStorage.setItem(`refresh_attempt_${key}`, attempts.toString());
  return attempts;
};

const clearRefreshAttempts = (key: string) => {
  sessionStorage.removeItem(`refresh_attempt_${key}`);
};

// 응답 인터셉터: 401 발생 시 토큰 갱신 로직 수행
client.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const requestKey = `${originalRequest.method}-${originalRequest.url}`;

    // 특정 URL에 대해서는 인터셉터 로직을 건너뜁니다.
    const excludeUrls = [
      "/api/token/",
      "/api/token/refresh/",
      "/api/auth/logout/",
    ];
    if (excludeUrls.some((url) => originalRequest.url.includes(url))) {
      return Promise.reject(error);
    }

    if (error.response?.status === 401 && !originalRequest._retry) {
      const attempts = getRefreshAttempts(requestKey);

      if (attempts >= MAX_REFRESH_ATTEMPTS) {
        console.log("Token refresh max attempts exceeded");
        localStorage.removeItem("access_token");
        Object.keys(sessionStorage)
          .filter((key) => key.startsWith("refresh_attempt_"))
          .forEach((key) => sessionStorage.removeItem(key));
        window.location.href = "/login";
        return Promise.reject(error);
      }

      try {
        originalRequest._retry = true;
        incrementRefreshAttempts(requestKey);

        // 토큰 갱신 요청
        const response = await client.post("/api/token/refresh/");
        const { access } = response.data;

        if (access) {
          localStorage.setItem("access_token", access); // 새 액세스 토큰 저장
          originalRequest.headers.Authorization = `Bearer ${access}`;
          clearRefreshAttempts(requestKey); // 시도 횟수 초기화
          return client(originalRequest); // 원래 요청 재시도
        }
      } catch (refreshError) {
        console.log("Token refresh failed:", refreshError);
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);
