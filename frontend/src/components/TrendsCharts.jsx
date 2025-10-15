import React, { useEffect, useState } from "react";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from "chart.js";
import api from "@/api/client";
import { useOrg } from "@/context/OrgContext";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

export default function TrendsCharts() {
  const { currentOrgId } = useOrg();
  const [series, setSeries] = useState([]);
  const [error, setError] = useState("");

  const load = async () => {
    setError("");
    try {
      const { data } = await api.get(`/dashboard/finance/trends?org_id=${currentOrgId}&periods=6`);
      setSeries(data.series || []);
    } catch (e) {
      setError(e?.response?.data?.detail || "Failed to load trends");
    }
  };

  useEffect(()=>{ if (currentOrgId) load(); }, [currentOrgId]);

  const renderChart = (kpiKey, label) => {
    const s = series.find(x => x.kpi === kpiKey);
    if (!s || !s.points || s.points.length < 2) return <div className="text-sm text-gray-500">No data</div>;
    const labels = s.points.map(p => p[0]);
    const values = s.points.map(p => p[1]);
    const data = {
      labels,
      datasets: [{ label, data: values, borderColor: "#111", backgroundColor: "rgba(0,0,0,0.05)", tension: 0.2, pointRadius: 2 }]
    };
    const options = { responsive: true, plugins: { legend: { display: false } }, scales: { y: { ticks: { color: "#111"}}, x: { ticks: { color: "#555"}} } };
    return <Line data={data} options={options} />;
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4" data-testid="trends-section">
      <div className="border rounded bg-white p-3"><div className="text-sm mb-2">Revenue</div>{renderChart("revenue","Revenue")}</div>
      <div className="border rounded bg-white p-3"><div className="text-sm mb-2">GM%</div>{renderChart("gm_pct","GM%")}</div>
      <div className="border rounded bg-white p-3"><div className="text-sm mb-2">OPEX</div>{renderChart("opex","OPEX")}</div>
      <div className="border rounded bg-white p-3"><div className="text-sm mb-2">DSO</div>{renderChart("dso_days","DSO")}</div>
      {error && <div className="text-red-600 text-sm" role="alert" aria-live="polite">{error}</div>}
    </div>
  );
}
