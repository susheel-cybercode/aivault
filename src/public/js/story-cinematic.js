/* AIVault — Cinematic Story Engine
   Renders an animated typewriter story sequence before each chapter mission.
   Users can skip at any time to jump straight to the mission content. */

(function () {
  'use strict';

  const TYPE_SPEED = 24;
  const LINE_DELAY = 700;

  function StoryEngine(opts) {
    this.lines = opts.lines || [];
    this.overlay = opts.overlay;
    this.container = opts.container;
    this.skipBtn = opts.skipBtn;
    this.beginBtn = opts.beginBtn;
    this.onComplete = opts.onComplete || function () {};
    this.timers = [];
    this.skipped = false;
  }

  StoryEngine.prototype.typewriter = function (el, text, callback) {
    const self = this;
    el.classList.add('active');
    el.innerHTML = '<span class="tw-cursor"></span>';
    let i = 0;
    function tick() {
      if (self.skipped) {
        el.textContent = text;
        el.classList.remove('active');
        el.classList.add('done');
        callback();
        return;
      }
      if (i < text.length) {
        el.innerHTML = text.slice(0, i + 1) + '<span class="tw-cursor"></span>';
        i++;
        self.timers.push(setTimeout(tick, TYPE_SPEED));
      } else {
        el.innerHTML = text;
        el.classList.remove('active');
        el.classList.add('done');
        callback();
      }
    }
    tick();
  };

  StoryEngine.prototype.run = function () {
    const self = this;
    let idx = 0;

    function nextLine() {
      if (self.skipped) {
        self.finish();
        return;
      }
      if (idx >= self.lines.length) {
        self.showBeginButton();
        return;
      }
      const lineEl = self.container.children[idx];
      if (!lineEl) {
        idx++;
        nextLine();
        return;
      }
      self.typewriter(lineEl, self.lines[idx], function () {
        idx++;
        self.timers.push(setTimeout(nextLine, LINE_DELAY));
      });
    }

    // Start after initial badge fade-in
    self.timers.push(setTimeout(nextLine, 1000));
  };

  StoryEngine.prototype.showBeginButton = function () {
    const self = this;
    if (self.skipBtn) self.skipBtn.style.display = 'none';
    if (self.beginBtn) {
      self.beginBtn.classList.add('show');
      self.beginBtn.addEventListener('click', function () {
        self.finish();
      });
    } else {
      self.finish();
    }
  };

  StoryEngine.prototype.finish = function () {
    const self = this;
    self.timers.forEach(clearTimeout);
    if (self.overlay) {
      self.overlay.classList.add('fade-out');
      setTimeout(function () {
        if (self.overlay.parentNode) self.overlay.parentNode.removeChild(self.overlay);
        self.onComplete();
      }, 800);
    }
  };

  StoryEngine.prototype.skip = function () {
    this.skipped = true;
    this.timers.forEach(clearTimeout);
    this.finish();
  };

  // Boot strapped via window.__story data
  function boot() {
    const overlay = document.getElementById('story-overlay');
    if (!overlay) return;

    const container = document.getElementById('story-lines');
    const skipBtn = document.getElementById('story-skip');
    const beginBtn = document.getElementById('story-begin');
    const lines = window.__storyLines || [];

    // Fill placeholder line elements
    lines.forEach(function () {
      if (container) {
        const div = document.createElement('div');
        div.className = 'story-line';
        container.appendChild(div);
      }
    });

    const engine = new StoryEngine({
      lines: lines,
      overlay: overlay,
      container: container,
      skipBtn: skipBtn,
      beginBtn: beginBtn,
      onComplete: function () {
        document.body.style.overflow = '';
      },
    });

    if (skipBtn) {
      skipBtn.addEventListener('click', function () {
        engine.skip();
      });
    }

    document.body.style.overflow = 'hidden';
    engine.run();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
