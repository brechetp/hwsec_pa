/**********************************************************************************
Copyright Institut Telecom
Contributors: Renaud Pacalet (renaud.pacalet@telecom-paristech.fr)

This software is a computer program whose purpose is to experiment timing and
power attacks against crypto-processors.

This software is governed by the CeCILL license under French law and
abiding by the rules of distribution of free software.  You can  use,
modify and/ or redistribute the software under the terms of the CeCILL
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info".

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability.

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or
data to be ensured and,  more generally, to use and operate it in the
same conditions as regards security.

The fact that you are presently reading this means that you have had
knowledge of the CeCILL license and that you accept its terms. For more
information see the LICENCE-fr.txt or LICENSE-en.txt files.
**********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <tr_pcc.h>
#include <utils.h>
#include <traces.h>
#include <des.h>

/* The P permutation table, as in the standard. The first entry (16) is the
 * position of the first (leftmost) bit of the result in the input 32 bits word.
 * Used to convert target bit index into SBox index (just for printed summary
 * after attack completion). */
int p_table[32] = {
  16, 7, 20, 21,
  29, 12, 28, 17,
  1, 15, 23, 26,
  5, 18, 31, 10,
  2, 8, 24, 14,
  32, 27, 3, 9,
  19, 13, 30, 6,
  22, 11, 4, 25
};

tr_context ctx;                 /* Trace context (see traces.h) */
int target_bit;                 /* Index of target bit. */
int target_sbox;                /* Index of target SBox. */
int best_guess;                 /* Best guess */
int best_idx;                   /* Best argmax */
uint64_t k16;
float best_max;                 /* Best max sample value */
float *dpa[64];                 /* 64 DPA traces */

/* A function to allocate cipher texts and power traces, read the
 * datafile and store its content in allocated context. */
void read_datafile (char *name, int n);

/* Compute the average power trace of the traces context ctx, print it in file
 * <prefix>.dat and print the corresponding gnuplot command in <prefix>.cmd. In
 * order to plot the average power trace, type: $ gnuplot -persist <prefix>.cmd
 * */
void average (char *prefix);

/* Decision function: takes a ciphertext and returns an array of 64 values for
 * an intermediate DES data, one per guess on a 6-bits subkey. In this example
 * the decision is the computed value of bit index <target_bit> of L15. Each of
 * the 64 decisions is thus 0 or 1.*/
void decision (uint64_t ct, tr_pcc_context *pcc_ctx, int sbox);

/* Filtered_ham_dist: takes two 32 bit numbers and an SBox number and returns
 * the Hamming distance between the two SBOX outputs */

int filtered_ham_dist (uint64_t r_1, uint64_t r2, int sbox);

/* Apply P. Kocher's DPA algorithm based on decision function. Computes 64 DPA
 * traces dpa[0..63], best_guess (6-bits subkey corresponding to highest DPA
 * peak), best_idx (index of sample with maximum value in best DPA trace) and
 * best_max (value of sample with maximum value in best DPA trace). */
void dpa_attack (void);

int
main (int argc, char **argv)
{
  int n;                        /* Number of experiments to use. */
  int g;                        /* Guess on a 6-bits subkey */

  /************************************************************************/
  /* Before doing anything else, check the correctness of the DES library */
  /************************************************************************/
  if (!des_check ())
    {
      ERROR (-1, "DES functional test failed");
    }

  /*************************************/
  /* Check arguments and read datafile */
  /*************************************/
  /* If invalid number of arguments (including program name), exit with error
   * message. */
  if (argc != 3)
    {
      ERROR (-1, "usage: dpa <file> <n> <b>\n  <file>: name of the traces file in HWSec format\n          (e.g. /datas/teaching/courses/HWSec/labs/data/HWSecTraces10000x00800.hws)\n  <n>: number of experiments to use\n  <b>: index of target bit in L15 (1 to 32, as in DES standard)\n");
    }
  /* Number of experiments to use is argument #2, convert it to integer and
   * store the result in variable n. */
  n = atoi (argv[2]);
  if (n < 1)                    /* If invalid number of experiments. */
    {
      ERROR (-1, "invalid number of experiments: %d (shall be greater than 1)", n);
    }
  /* Compute index of corresponding SBox */
  /* Read power traces and ciphertexts. Name of data file is argument #1. n is
   * the number of experiments to use. */
  read_datafile (argv[1], n);

  /*****************************************************************************
   * Compute and print average power trace. Store average trace in file
   * "average.dat" and gnuplot command in file "average.cmd". In order to plot
   * the average power trace, type: $ gnuplot -persist average.cmd
   *****************************************************************************/
/*  average ("average"); */

  /***************************************************************
   * Attack target bit in L15=R14 with P. Kocher's DPA technique *
   ***************************************************************/
  k16 = 0;
  dpa_attack ();
  printf("%012" PRIx64"\n", k16);
  uint64_t key;    /* 64 bits secret key */
  uint64_t ks[16]; /* Key schedule (array of 16 round keys) */
  key = tr_key (ctx); /* Extract 64 bits secret key from context */
  des_ks (ks, key);   /* Compute key schedule */
  if (k16 == ks[15])  /* If guessed 16th round key matches actual 16th round key */
      printf ("We got it!!!\n"); /* Cheers */
  else
      printf ("Too bad...\n");   /* Cry */

  /*****************************************************************************
   * Print the 64 DPA traces in a data file named dpa.dat. Print corresponding
   * gnuplot commands in a command file named dpa.cmd. All DPA traces are
   * plotted in blue but the one corresponding to the best guess which is
   * plotted in red with the title "Trace X (0xY)" where X and Y are the decimal
   * and heaxdecimal forms of the 6 bits best guess.
   *****************************************************************************/
  /* Plot DPA traces in dpa.dat, gnuplot commands in dpa.cmd */

  /*****************
   * Print summary *
   *****************/

  /*************************
   * Free allocated traces *
   *************************/
  for (g = 0; g < 64; g++)      /* For all guesses for 6-bits subkey */
    {
      tr_free_trace (ctx, dpa[g]);
    }
  tr_free (ctx);                /* Free traces context */
  return 0;                     /* Exits with "everything went fine" status. */
}

void
read_datafile (char *name, int n)
{
  int tn;

  ctx = tr_init (name, n);
  tn = tr_number (ctx);
  if (tn != n)
    {
      tr_free (ctx);
      ERROR (-1, "Could not read %d experiments from traces file. Traces file contains %d experiments.", n, tn);
    }
}

void
average (char *prefix)
{
  int i;                        /* Loop index */
  int n;                        /* Number of traces. */
  float *sum;                   /* Power trace for the sum */
  float *avg;                   /* Power trace for the average */

  n = tr_number (ctx);          /* Number of traces in context */
  sum = tr_new_trace (ctx);     /* Allocate a new power trace for the sum. */
  avg = tr_new_trace (ctx);     /* Allocate a new power trace for the average. */
  tr_init_trace (ctx, sum, 0.0);        /* Initialize sum trace to all zeros. */
  for (i = 0; i < n; i++)       /* For all power traces */
    {
      tr_acc (ctx, sum, tr_trace (ctx, i));     /* Accumulate trace #i to sum */
    }                           /* End for all power traces */
  /* Divide trace sum by number of traces and put result in trace avg */
  tr_scalar_div (ctx, avg, sum, (float) (n));
  tr_plot (ctx, prefix, 1, -1, &avg);
  printf ("Average power trace stored in file '%s.dat'. In order to plot it, type:\n", prefix);
  printf ("$ gnuplot -persist %s.cmd\n", prefix);
  tr_free_trace (ctx, sum);     /* Free sum trace */
  tr_free_trace (ctx, avg);     /* Free avg trace */
}

void
decision (uint64_t ct, tr_pcc_context* pcc_ctx, int sbox)
{
  int g;                        /* Guess */
  float h_d;                    /* Hamming distance (our PCC classes) */
  uint64_t r16l16;              /* R16|L16 (64 bits state register before final permutation) */
  uint64_t l16;                 /* L16 (as in DES standard) */
  uint64_t r16;                 /* R16 (as in DES standard) */
  uint64_t er15;                /* E(R15) = E(L16) */
  uint64_t l15;                 /* L15 (as in DES standard) */
  uint64_t rk;                  /* Value of last round key */


  r16l16 = des_ip (ct);         /* Compute R16|L16 */
  l16 = des_right_half (r16l16);        /* Extract right half */
  r16 = des_left_half (r16l16); /* Extract left half */
  er15 = des_e (l16);           /* Compute E(R15) = E(L16) */
  /* For all guesses (64). rk is a 48 bits last round key with all 6-bits
   * subkeys equal to current guess g (nice trick, isn't it?). */
  for (g = 0, rk = UINT64_C (0); g < 64; g++, rk += UINT64_C (0x041041041041))
    {
      l15 = r16 ^ ( des_p (des_sboxes (er15 ^ rk)));     /* computes hyp. l15 */

      h_d = (float) filtered_ham_dist(l15, l16, sbox);      /* Hamming distance between SBoxes outputs */
      tr_pcc_insert_y(*pcc_ctx, g, h_d);     /* Insert realization h_d of rv# g in context pcc_ctx */

    }                           /* End for guesses */
}

int
filtered_ham_dist (uint64_t r_1, uint64_t r_2, int sbox)
{
  uint64_t np_r1, np_r2;

  np_r1 = des_n_p(r_1); /* We undo the P permutation */
  np_r2 = des_n_p(r_2);

  return hamming_distance ((np_r1 >> (sbox-1)*4) & UINT64_C (0xf), (np_r2 >> (sbox-1)*4) & UINT64_C (0xf)) ;
}


void
dpa_attack (void)
{
  int i;                        /* Loop index */
  int n;                        /* Number of traces. */
  int idx;                      /* Argmax (index of sample with maximum value in a trace) */
  int sbox;                     /* SBox # */

  float *t;                     /* Power trace */
  float max;                    /* Max sample value in a trace */

  tr_pcc_context pcc_ctx;

  uint64_t ct;                  /* Ciphertext */

  n = tr_number (ctx);          /* Number of traces in context */
  for (sbox = 1; sbox <= 8; sbox++) /* For all SBoxes */
  {

    pcc_ctx = tr_pcc_init(800, 64);   /* 800 samples per power trace, 64 r.v */
    for (i = 0; i < n; i++)       /* For all experiments */
      {
        t = tr_trace (ctx, i);    /* Get power trace */
        ct = tr_ciphertext (ctx, i);      /* Get ciphertext */

        tr_pcc_insert_x(pcc_ctx, t);      /* insert the trace in the Pearson context */

        decision(ct, &pcc_ctx, sbox);      /* fills the PC with Y realizations */




      }                           /* End for experiments */
    tr_pcc_consolidate(pcc_ctx);

    uint64_t best_guess, g;
    for(g = 0; g < 64; g++)
    {
      float *trace;
      trace = tr_pcc_get_pcc(pcc_ctx, g); /* we get the PCC trace */
      dpa[g] = tr_new_trace(ctx); /* We allocate a new trace */
      tr_acc(ctx, dpa[g], trace); /* We store the PCC trace in the newly allocated trace */
      max = tr_max(ctx, dpa[g], &idx); /* We take the maximum spike */
      if ((max > best_max) || g==0) /* If the spike is greater than before */
      {
        best_max = max;
        best_guess = g; /* The key must be this one */
        best_idx = idx;
      }

    }
    k16 |= (best_guess << (sbox-1)*6); /* We construct the key */

  }


    
}
