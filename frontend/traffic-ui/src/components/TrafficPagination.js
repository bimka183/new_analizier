import React from "react";
import Button from "../ui/button";
import { PAGE_SIZE_OPTIONS } from "../constants/trafficApp";

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

function TrafficPagination({
  currentPage,
  totalPages,
  totalRows = 0,
  itemsPerPage,
  onItemsPerPageChange,
  onPrev,
  onNext,
}) {
  const safeTotalPages = Math.max(1, totalPages);
  const start =
    totalRows === 0 ? 0 : (currentPage - 1) * itemsPerPage + 1;
  const end =
    totalRows === 0
      ? 0
      : Math.min(currentPage * itemsPerPage, totalRows);

  const rangeLabel =
    totalRows === 0
      ? "Нет строк для отображения"
      : `Отображаются строки с ${start} по ${end} из ${totalRows}`;

  const pageSizeId = "traffic-pagination-page-size";

  return (
    <div className="app__pagination">
      <div className="app__pagination-lead">
        <span className="app__pagination-range">{rangeLabel}</span>
      </div>
      <div className="app__pagination-controls">
        <Button disabled={currentPage === 1} onClick={onPrev} icon={<PrevIcon />}>
          Prev
        </Button>

        <span className="app__page-info">
          {currentPage} / {safeTotalPages}
        </span>

        <Button
          disabled={currentPage >= safeTotalPages}
          onClick={onNext}
          icon={<NextIcon />}
          iconPosition="right"
        >
          Next
        </Button>
      </div>
      <div className="app__pagination-tail">
        <div className="app__pagination-page-size">
          <label htmlFor={pageSizeId}>Rows per page</label>
          <select
            id={pageSizeId}
            aria-label="Rows per page"
            value={itemsPerPage}
            onChange={(event) =>
              onItemsPerPageChange(Number(event.target.value))
            }
          >
            {PAGE_SIZE_OPTIONS.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
}

export default TrafficPagination;
