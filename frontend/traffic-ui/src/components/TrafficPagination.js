import React from "react";
import Button from "../ui/button";

function PrevIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M15.4 6L9.4 12l6 6-1.4 1.4L6.6 12l7.4-7.4L15.4 6z" fill="currentColor" />
    </svg>
  );
}

function NextIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M8.6 18l6-6-6-6L10 4.6l7.4 7.4-7.4 7.4L8.6 18z" fill="currentColor" />
    </svg>
  );
}

function TrafficPagination({ currentPage, totalPages, onPrev, onNext }) {
  return (
    <div className="app__pagination">
      <Button disabled={currentPage === 1} onClick={onPrev} icon={<PrevIcon />}>
        Prev
      </Button>

      <span className="app__page-info">
        {currentPage} / {totalPages}
      </span>

      <Button
        disabled={currentPage >= totalPages}
        onClick={onNext}
        icon={<NextIcon />}
        iconPosition="right"
      >
        Next
      </Button>
    </div>
  );
}

export default TrafficPagination;
