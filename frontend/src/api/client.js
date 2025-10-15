import axios from "axios";

const BASE_URL = (process.env.REACT_APP_BACKEND_URL || "").replace(/\/$/, "");
const api = axios.create({
  baseURL: `${BASE_URL}/api`,
});

let isRefreshing = false;
let refreshSubscribers = [];

function onRefreshed(newToken) {
  refreshSubscribers.forEach((cb) => cb(newToken));
  refreshSubscribers = [];
}

function addRefreshSubscriber(cb) {
  refreshSubscribers.push(cb);
}

export const tokenStore = {
  get access() {
    return localStorage.getItem("access_token");
  },
  set access(val) {
    if (!val) localStorage.removeItem("access_token");
    else localStorage.setItem("access_token", val);
  },
  get refresh() {
    return localStorage.getItem("refresh_token");
  },
  set refresh(val) {
    if (!val) localStorage.removeItem("refresh_token");
    else localStorage.setItem("refresh_token", val);
  },
  get orgId() {
    return localStorage.getItem("current_org_id");
  },
  set orgId(val) {
    if (!val) localStorage.removeItem("current_org_id");
    else localStorage.setItem("current_org_id", val);
  },
};

api.interceptors.request.use((config) => {
  const token = tokenStore.access;
  const orgId = tokenStore.orgId;
  if (token) config.headers["Authorization"] = `Bearer ${token}`;
  if (orgId) config.headers["X-Org-Id"] = orgId;
  return config;
});

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const originalRequest = error.config || {};
    if (error.response && error.response.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve) => {
          addRefreshSubscriber((newToken) => {
            originalRequest.headers["Authorization"] = `Bearer ${newToken}`;
            resolve(api(originalRequest));
          });
        });
      }
      originalRequest._retry = true;
      isRefreshing = true;
      try {
        const refresh_token = tokenStore.refresh;
        if (!refresh_token) throw new Error("No refresh token");
        const { data } = await api.post("/auth/refresh", { refresh_token });
        tokenStore.access = data.access_token;
        tokenStore.refresh = data.refresh_token;
        isRefreshing = false;
        onRefreshed(data.access_token);
        originalRequest.headers["Authorization"] = `Bearer ${data.access_token}`;
        return api(originalRequest);
      } catch (e) {
        isRefreshing = false;
        tokenStore.access = null;
        tokenStore.refresh = null;
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

export default api;
