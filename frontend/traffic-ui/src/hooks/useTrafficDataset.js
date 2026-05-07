import { useCallback, useEffect, useRef, useState } from "react";
import { API_BASE_URL } from "../constants/trafficApp";

export function useTrafficDataset() {
  const [allData, setAllData] = useState([]);
  const apiBaseRef = useRef(API_BASE_URL);

  const fetchAllData = useCallback(async () => {
    const response = await fetch(
      `${apiBaseRef.current}/api/traffic?page=1&limit=10000`
    );
    const result = await response.json();
    setAllData(result.data || []);
  }, []);

  useEffect(() => {
    fetchAllData();
  }, [fetchAllData]);

  useEffect(() => {
    const wsUrl = apiBaseRef.current
      .replace(/^http:/, "ws:")
      .replace(/^https:/, "wss:");
    const ws = new WebSocket(`${wsUrl}/ws`);

    ws.onmessage = (event) => {
      const newData = JSON.parse(event.data);

      setAllData((prev) => {
        if (prev.find((i) => i.id === newData.id)) return prev;
        return [...prev, newData];
      });
    };

    return () => ws.close();
  }, []);

  return { allData, apiBaseRef, fetchAllData };
}
