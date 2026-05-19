import React from "react";
import { FOOTER_CREATORS } from "../../constants/footerCreators";
import "./Footer.scss";

const TELEGRAM_ICON_SRC = "/svg/telegram.svg";
const SAKURA_LEAF_SRC = `${process.env.PUBLIC_URL}/png/sakura_18655501.png`;
const SAKURA_LEAF_COUNT = 5;
const SAKURA_LEAF_STYLE = {
  backgroundImage: `url(${SAKURA_LEAF_SRC})`,
};
const POOP_ICON_SRC = `${process.env.PUBLIC_URL}/svg/poop.svg`;
const POOP_PIECE_STYLE = {
  backgroundImage: `url(${POOP_ICON_SRC})`,
};

const POOP_PYRAMID_ROWS = [
  ["site-footer__poop-piece--1"],
  ["site-footer__poop-piece--2", "site-footer__poop-piece--3"],
  [
    "site-footer__poop-piece--4",
    "site-footer__poop-piece--5",
    "site-footer__poop-piece--6",
  ],
];

function getCreatorClassName(person) {
  const classes = ["site-footer__creator"];
  if (person.highlight) {
    classes.push("site-footer__creator--featured");
  }
  if (person.sakura) {
    classes.push("site-footer__creator--sakura");
  }
  if (person.devopsPoop) {
    classes.push("site-footer__creator--devops-poop");
  }
  return classes.join(" ");
}

function Footer() {
  return (
    <footer className="site-footer" aria-label="Информация о проекте" tabIndex={0}>
      <p className="site-footer__peek" aria-hidden="true">
        О проекте · Создатели
      </p>

      <div className="site-footer__panel">
        <div className="site-footer__inner">
          <section className="site-footer__about" aria-labelledby="footer-about-heading">
            <h3 id="footer-about-heading" className="site-footer__heading">
              О проекте
            </h3>
            <p className="site-footer__text">
              <strong>PCAP Traffic Analyzer</strong> — веб-приложение для анализа
              сетевого трафика: загружаете .pcap, бэкенд группирует пакеты в потоки
              и прогоняет их через детекторы угроз (DDoS, перегрузка, сканирование,
              черви и др.). Результаты отображаются на интерактивных дашбордах и в
              журнале трафика.
            </p>
          </section>

          <section
            className="site-footer__creators"
            aria-labelledby="footer-creators-heading"
          >
            <h3 id="footer-creators-heading" className="site-footer__heading">
              Создатели
            </h3>
            <ul className="site-footer__creators-list">
              {FOOTER_CREATORS.map((person) => (
                <li key={person.id} className={getCreatorClassName(person)}>
                  {person.sakura ? (
                    <span className="site-footer__sakura-leaves" aria-hidden="true">
                      {Array.from({ length: SAKURA_LEAF_COUNT }, (_, index) => (
                        <span
                          key={`sakura-${person.id}-${index}`}
                          className={`site-footer__sakura-leaf site-footer__sakura-leaf--${index + 1}`}
                          style={SAKURA_LEAF_STYLE}
                        />
                      ))}
                    </span>
                  ) : null}
                  {person.devopsPoop ? (
                    <span className="site-footer__poop-pyramid" aria-hidden="true">
                      {POOP_PYRAMID_ROWS.map((rowPieces, rowIndex) => (
                        <span
                          key={`poop-row-${person.id}-${rowIndex}`}
                          className="site-footer__poop-row"
                        >
                          {rowPieces.map((pieceClass) => (
                            <span
                              key={`${person.id}-${pieceClass}`}
                              className={`site-footer__poop-piece ${pieceClass}`}
                              style={POOP_PIECE_STYLE}
                            />
                          ))}
                        </span>
                      ))}
                    </span>
                  ) : null}
                  <span className="site-footer__creator-role">{person.role}</span>
                  <a
                    className="site-footer__creator-link"
                    href={`https://t.me/${person.telegram}`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <img
                      className="site-footer__telegram-icon"
                      src={TELEGRAM_ICON_SRC}
                      alt=""
                      width={18}
                      height={18}
                      aria-hidden="true"
                    />
                    <span className="site-footer__creator-handle">
                      @{person.telegram}
                    </span>
                  </a>
                </li>
              ))}
            </ul>
          </section>
        </div>

        <p className="site-footer__copy">
          © {new Date().getFullYear()} PCAP Traffic Analyzer
        </p>
      </div>
    </footer>
  );
}

export default Footer;
