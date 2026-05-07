import React from "react";
import Button from "../ui/button";

function UploadIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M12 4l4 4h-3v6h-2V8H8l4-4zm-7 12h14v4H5v-4z"
        fill="currentColor"
      />
    </svg>
  );
}

function UploadControls({ setFile, onUpload }) {
  return (
    <div className="app__controls">
      <input type="file" onChange={(event) => setFile(event.target.files?.[0] || null)} />
      <Button onClick={onUpload} icon={<UploadIcon />}>
        Upload PCAP
      </Button>
    </div>
  );
}

export default UploadControls;
