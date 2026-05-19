import React, {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import "./ScrollBar.scss";

const MIN_THUMB_PX = 28;

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

/**
 * Custom vertical scrollbar: hides native bar, syncs thumb with scroll position.
 */
function ScrollBar({
  children,
  className = "",
  contentClassName = "",
  ariaLabel = "Scrollable content",
}) {
  const viewportRef = useRef(null);
  const trackRef = useRef(null);
  const dragRef = useRef(null);

  const [thumb, setThumb] = useState({
    visible: false,
    heightPx: MIN_THUMB_PX,
    topPx: 0,
  });

  const syncThumb = useCallback(() => {
    const viewport = viewportRef.current;
    const track = trackRef.current;
    if (!viewport || !track) return;

    const { scrollTop, scrollHeight, clientHeight } = viewport;
    const trackHeight = track.clientHeight;

    if (scrollHeight <= clientHeight + 1 || trackHeight <= 0) {
      setThumb({ visible: false, heightPx: MIN_THUMB_PX, topPx: 0 });
      return;
    }

    const maxScroll = scrollHeight - clientHeight;
    const thumbHeight = clamp(
      (clientHeight / scrollHeight) * trackHeight,
      MIN_THUMB_PX,
      trackHeight
    );
    const maxThumbTop = trackHeight - thumbHeight;
    const topPx =
      maxScroll > 0 ? (scrollTop / maxScroll) * maxThumbTop : 0;

    setThumb({ visible: true, heightPx: thumbHeight, topPx });
  }, []);

  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return undefined;

    syncThumb();

    const onScroll = () => syncThumb();
    viewport.addEventListener("scroll", onScroll, { passive: true });

    const ro = new ResizeObserver(() => syncThumb());
    ro.observe(viewport);
    if (viewport.firstElementChild) {
      ro.observe(viewport.firstElementChild);
    }

    return () => {
      viewport.removeEventListener("scroll", onScroll);
      ro.disconnect();
    };
  }, [syncThumb, children]);

  const scrollToThumbTop = useCallback(
    (thumbTopPx, thumbHeightPx) => {
      const viewport = viewportRef.current;
      const track = trackRef.current;
      if (!viewport || !track) return;

      const trackHeight = track.clientHeight;
      const thumbHeight = thumbHeightPx ?? thumb.heightPx;
      const maxThumbTop = Math.max(trackHeight - thumbHeight, 1);
      const ratio = clamp(thumbTopPx / maxThumbTop, 0, 1);
      const maxScroll = viewport.scrollHeight - viewport.clientHeight;
      viewport.scrollTop = ratio * maxScroll;
    },
    [thumb.heightPx]
  );

  const onTrackPointerDown = (event) => {
    if (event.target !== trackRef.current) return;
    const track = trackRef.current;
    if (!track) return;
    const rect = track.getBoundingClientRect();
    const y = event.clientY - rect.top - thumb.heightPx / 2;
    scrollToThumbTop(y, thumb.heightPx);
  };

  const onThumbPointerDown = (event) => {
    event.preventDefault();
    event.stopPropagation();

    const viewport = viewportRef.current;
    const track = trackRef.current;
    if (!viewport || !track) return;

    const startY = event.clientY;
    const startThumbTop = thumb.topPx;
    const thumbHeight = thumb.heightPx;

    dragRef.current = { active: true };

    const onMove = (e) => {
      if (!dragRef.current?.active) return;
      const delta = e.clientY - startY;
      scrollToThumbTop(startThumbTop + delta, thumbHeight);
    };

    const onUp = () => {
      dragRef.current = null;
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);
  };

  const rootClass = ["ui-scroll-bar", className].filter(Boolean).join(" ");
  const contentClass = ["ui-scroll-bar__content", contentClassName]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={rootClass}>
      <div
        ref={viewportRef}
        className="ui-scroll-bar__viewport"
        tabIndex={0}
        aria-label={ariaLabel}
      >
        <div className={contentClass}>{children}</div>
      </div>
      <div
        ref={trackRef}
        className="ui-scroll-bar__track"
        aria-hidden={!thumb.visible}
        onPointerDown={onTrackPointerDown}
      >
        {thumb.visible ? (
          <div
            role="slider"
            className="ui-scroll-bar__thumb"
            style={{
              height: `${thumb.heightPx}px`,
              transform: `translateY(${thumb.topPx}px)`,
            }}
            onPointerDown={onThumbPointerDown}
            aria-label="Scroll position"
            aria-valuemin={0}
            aria-valuemax={100}
            tabIndex={-1}
          />
        ) : null}
      </div>
    </div>
  );
}

export default ScrollBar;
