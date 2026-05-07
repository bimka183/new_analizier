import React from "react";
import { getAnomaly, getRowClassName } from "../utils/traffic";

/**
 * Original flat traffic table (one row per packet). Kept for reuse / comparison.
 */
function TrafficTablePlain({ data }) {
  return (
    <table className="traffic-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Flow</th>
          <th>Time</th>
          <th>Source</th>
          <th>Destination</th>
          <th>Src Port</th>
          <th>Dst Port</th>
          <th>Flags</th>
          <th>Volume</th>
          <th>Anomaly</th>
        </tr>
      </thead>

      <tbody>
        {data.map((item) => (
          <tr key={item.id} className={getRowClassName(getAnomaly(item))}>
            <td>{item.id}</td>
            <td>{item.flow_id}</td>
            <td>{item.timestamp}</td>
            <td>{item.source_ip}</td>
            <td>{item.destination_ip}</td>
            <td>{item.source_port}</td>
            <td>{item.destination_port}</td>
            <td>{item.flags}</td>
            <td>{item.traffic_volume}</td>
            <td>{getAnomaly(item)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default TrafficTablePlain;
