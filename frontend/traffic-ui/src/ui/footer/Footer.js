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
const MAGNIFIER_ICON_SRC = `${process.env.PUBLIC_URL}/svg/icons8-лупа.svg`;
const RESEARCH_MAGNIFIER_STYLE = {
  backgroundImage: `url(${MAGNIFIER_ICON_SRC})`,
};
const DOCKER_TRAIN_ICON_SRC = `${process.env.PUBLIC_URL}/svg/docker-svgrepo-com.svg`;
const BACKEND_TRAIN_CAR_STYLE = {
  backgroundImage: `url(${DOCKER_TRAIN_ICON_SRC})`,
};
const BACKEND_TRAIN_CAR_COUNT = 3;
const RESEARCH_BOOK_SRC = `${process.env.PUBLIC_URL}/svg/books.svg`;
const RESEARCH_XP_ORB_SRC = `${process.env.PUBLIC_URL}/png/Experience_Orb_Value_-32768-2.png`;
const RESEARCH_BOOK_STYLE = {
  backgroundImage: `url(${RESEARCH_BOOK_SRC})`,
};
const RESEARCH_XP_ORB_STYLE = {
  backgroundImage: `url(${RESEARCH_XP_ORB_SRC})`,
};
const RESEARCH_XP_ORB_COUNT = 3;
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
  if (person.researchMagnifier) {
    classes.push("site-footer__creator--research");
  }
  if (person.backendTrain) {
    classes.push("site-footer__creator--backend-train");
  }
  if (person.researchBooks) {
    classes.push("site-footer__creator--research-books");
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
                  {person.backendTrain ? (
                    <span className="site-footer__backend-train-scene" aria-hidden="true">
                      <span className="site-footer__backend-train">
                        {Array.from({ length: BACKEND_TRAIN_CAR_COUNT }, (_, index) => (
                          <span
                            key={`train-${person.id}-${index}`}
                            className="site-footer__backend-train-car"
                            style={BACKEND_TRAIN_CAR_STYLE}
                          />
                        ))}
                      </span>
                    </span>
                  ) : null}
                  {person.researchBooks ? (
                    <span className="site-footer__research-books-scene" aria-hidden="true">
                      <span className="site-footer__research-books-stack">
                        <span
                          className="site-footer__research-book"
                          style={RESEARCH_BOOK_STYLE}
                        />
                      </span>
                      {Array.from({ length: RESEARCH_XP_ORB_COUNT }, (_, index) => (
                        <span
                          key={`orb-${person.id}-${index}`}
                          className={`site-footer__research-xp-orb site-footer__research-xp-orb--${index + 1}`}
                          style={RESEARCH_XP_ORB_STYLE}
                        />
                      ))}
                    </span>
                  ) : null}
                  {person.researchMagnifier ? (
                    <span className="site-footer__research-scene" aria-hidden="true">
                      <span
                        className="site-footer__research-magnifier"
                        style={RESEARCH_MAGNIFIER_STYLE}
                      />
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
