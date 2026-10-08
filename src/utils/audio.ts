/**
 * Kavach Local Audio Chime & Warning System
 * Synthesizes an alert chime using the Web Audio API directly in the browser.
 * Zero external audio files or network requests required.
 */

export class KavachAudioAlert {
  static playAlertChime(): void {
    try {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();

      // Two-tone warning alert (high to low)
      const osc1 = ctx.createOscillator();
      const osc2 = ctx.createOscillator();
      const gain = ctx.createGain();

      osc1.type = 'triangle';
      osc1.frequency.setValueAtTime(659.25, ctx.currentTime); // E5
      osc1.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.28); // A4

      osc2.type = 'sine';
      osc2.frequency.setValueAtTime(329.63, ctx.currentTime); // E4
      osc2.frequency.exponentialRampToValueAtTime(220, ctx.currentTime + 0.28); // A3

      gain.gain.setValueAtTime(0.18, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.28);

      osc1.connect(gain);
      osc2.connect(gain);
      gain.connect(ctx.destination);

      osc1.start();
      osc2.start();
      osc1.stop(ctx.currentTime + 0.3);
      osc2.stop(ctx.currentTime + 0.3);
    } catch {}
  }
}
