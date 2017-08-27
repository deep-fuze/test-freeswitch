EXTRA_DIST =
SUBDIRS = 
AUTOMAKE_OPTIONS = gnu
PREFIX=$(prefix)
NAME = webrtcneteq

AM_CFLAGS    = $(new_AM_CFLAGS) -I./src -I../spandsp/src -I../opus-1.2.1/include
AM_CPPFLAGS  = $(AM_CFLAGS)
AM_LDFLAGS   = $(new_AM_LDFLAGS) -L.

DEFS = @DEFS@ -DWEBRTC_POSIX -DNETEQ_WIDEBAND -DNETEQ_32KHZ_WIDEBAND -DNETEQ_48KHZ_WIDEBAND -DNETEQ_G722_CODEC -DNETEQ_G711_CODEC -DNETEQ_OPUS_CODEC

lib_LTLIBRARIES = libwebrtcneteq.la 
libwebrtcneteq_la_SOURCES =	src/accelerate.c src/expand.c src/preemptive_expand.c \
			src/automode.c src/filter_ar_fast_q12.c src/random_vector.c \
			src/bgn_update.c src/filter_ma_fast_q12.c src/real_fft.c \
			src/bufstats_decision.c src/g711_interface.c src/recin.c \
			src/cng_internal.c src/g722_interface.c src/recout.c \
			src/codec_db.c src/ilbc_specific_functions.c src/rtcp.c \
			src/complex_bit_reverse.c src/levinson_durbin.c src/rtp.c \
			src/complex_fft.c src/mcu_address_init.c src/set_fs.c \
			src/copy_set_operations.c src/mcu_dsp_common.c src/signal_mcu.c \
			src/correlator.c src/mcu_reset.c src/spl_init.c \
			src/cross_correlation.c src/merge.c src/split_and_insert.c \
			src/division_operations.c src/min_distortion.c src/spl_sqrt_floor.c \
			src/dot_product_with_scale.c src/min_max_operations.c src/unmute_signal.c \
			src/downsample_fast.c src/mix_voice_unvoice.c src/vector_scaling_operations.c \
			src/dsp.c src/mute_signal.c src/webrtc_neteq.c \
			src/dsp_helpfunctions.c src/normal.c src/webrtc_neteq_if.c \
			src/dtmf_buffer.c src/packet_buffer.c src/dtmf_tonegen.c \
			src/peak_detection.c src/opus_interface.c src/resample_fractional.c
libwebrtcneteq_la_LDFLAGS = 	-avoid-version -no-undefined $(AM_LDFLAGS)

library_includedir =  $(prefix)/include
library_include_HEADERS = src/automode.h src/g711.h src/resample_by_2_internal.h \
			src/buffer_stats.h src/g711_interface.h src/rtcp.h \
			src/codec_db_defines.h src/g722_interface.h src/rtp.h \
			src/codec_db.h src/mcu_dsp_common.h src/signal_processing_library.h \
			src/complex_fft_tables.h src/mcu.h   src/spl_inl.h \
			src/cpu_features_wrapper.h src/neteq_defines.h src/typedefs.h \
			src/delay_logging.h src/neteq_error_codes.h src/webrtc_cng.h \
			src/dsp.h src/dsp_helpfunctions.h src/opus_interface.h \
			src/dtmf_buffer.h src/packet_buffer.h src/dtmf_tonegen.h src/real_fft.h \
			src/interface/neteq_statistics.h src/interface/webrtc_neteq_if.h \
			src/interface/webrtc_neteq.h src/interface/webrtc_neteq_internal.h \
			src/interface/webrtc_neteq_help_macros.h 

