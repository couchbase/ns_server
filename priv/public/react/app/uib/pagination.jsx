import React, { useState, useEffect } from 'react';
import { Pagination } from 'react-bootstrap';

const NgbPagination = ({
  page = 1,
  maxSize = 5,
  pageSize = 10,
  collectionSize = 0,
  onPageChange,
  prevLabel = '',
  nextLabel = '',
  onClick,
}) => {
  const [currentPage, setCurrentPage] = useState(page);
  const totalPages = Math.ceil(collectionSize / pageSize);

  useEffect(() => {
    const newTotalPages = Math.ceil(collectionSize / pageSize);
    if (collectionSize > 0 && currentPage === 0) {
      setCurrentPage(1);
    } else if (currentPage > newTotalPages) {
      setCurrentPage(newTotalPages);
    } else {
      setCurrentPage(page);
    }
  }, [page, collectionSize, pageSize]);

  const getPageNumbers = () => {
    let pages = [];
    let startPage = Math.max(1, currentPage - Math.floor(maxSize / 2));
    let endPage = Math.min(totalPages, startPage + maxSize - 1);

    if (endPage - startPage + 1 < maxSize) {
      startPage = Math.max(1, endPage - maxSize + 1);
    }

    for (let i = startPage; i <= endPage; i++) {
      pages.push(i);
    }
    return pages;
  };

  const handlePageClick = (newPage, event) => {
    if (onClick) {
      event.stopPropagation();
      onClick(event);
    }

    if (newPage >= 1 && newPage <= totalPages) {
      setCurrentPage(newPage);
      onPageChange?.(newPage);
    }
  };

  return (
    <Pagination>
      <Pagination.Prev
        onClick={(e) => handlePageClick(currentPage - 1, e)}
        disabled={currentPage === 1}
      >
        {prevLabel}
      </Pagination.Prev>

      {getPageNumbers().map((pageNum) => (
        <Pagination.Item
          key={pageNum}
          active={pageNum === currentPage}
          onClick={(e) => handlePageClick(pageNum, e)}
        >
          {pageNum}
        </Pagination.Item>
      ))}

      <Pagination.Next
        onClick={(e) => handlePageClick(currentPage + 1, e)}
        disabled={currentPage === totalPages}
      >
        {nextLabel}
      </Pagination.Next>
    </Pagination>
  );
};

export { NgbPagination };
