import React from "react";
import ProcessedFilesTable from "../components/ProcessedFilesTable";
import "./AnalyzedFilesPage.scss";

function AnalyzedFilesPage() {
  return (
    <section className="analyzed-files-page">
      <h2>Analyzed Files</h2>
      <p className="analyzed-files-page__lead">
        Previously uploaded PCAP files stored on the server. Click a row to open its
        full analysis on Analyze file.
      </p>
      <ProcessedFilesTable />
    </section>
  );
}

export default AnalyzedFilesPage;
