#!/usr/bin/perl
#!-*- coding: utf-8 -*-

=head1 NAME
 
PDL::API - making ndarrays from Perl and C/XS code
 
=head1 DESCRIPTION
 
A simple cookbook how to create ndarrays manually.
It covers both the Perl and the C/XS level.
Additionally, it describes the PDL core routines
that can be accessed from other modules. These
routines basically define the PDL API. If you need to
access ndarrays from C/XS you probably need to know
about these functions.
 
=head1 SYNOPSIS
 
  use PDL;
  sub mkmyndarray {
   ...
  }
 
=head1 Creating an ndarray manually from Perl
 
Sometimes you want to create an ndarray I<manually>
from binary data. You can do that at the Perl level.
Examples in the distribution include some of the
IO routines. The code snippet below illustrates the
required steps.
 
   use Carp;
   sub mkmyndarray {
     my $class = shift;
     my $pdl  = $class->new;
     $pdl->set_datatype($PDL_B);
     my @dims = (1,3,4);
     my $size = 1;
     for (@dims) { $size *= $_ }
     $pdl->setdims([@dims]);
     my $dref = $pdl->get_dataref();
 
     # read data directly from file
     open my $file, '<data.dat' or die "couldn't open data.dat";
     my $len = $size*PDL::Core::howbig($pdl->get_datatype);
     croak "couldn't read enough data" if
       read( $file, $$dref, $len) != $len;
     close $file;
     $pdl->upd_data();
 
     return $pdl;
   }
 
=head1 Creating an ndarray in C
 
The following example creates an ndarray at the C level.
We use the C<Inline> module which is a good way to interface
Perl and C, using the C<with> capability in L<Inline> 0.68+.
 
Note that to create a "scalar" ndarray (with no dimensions at all,
and a single element), just pass a zero-length C<dims> array, with
C<ndims> as zero.
 
   use PDL::LiteF;
 
   $x = myfloatseq(); # exercise our C ndarray constructor
 
   print $x->info,"\n";
 
   use Inline with => 'PDL';
   use Inline C;
   Inline->init; # useful if you want to be able to 'do'-load this script
 
   __DATA__
 
   __C__
 
   static pdl* new_pdl(int datatype, PDL_Indx dims[], int ndims)
   {
     pdl *p = PDL->pdlnew();
     PDL->setdims (p, dims, ndims);  /* set dims */
     p->datatype = datatype;         /* and data type */
     PDL->allocdata (p);             /* allocate the data chunk */
 
     return p;
   }
 
   pdl* myfloatseq()
   {
     PDL_Indx dims[] = {5,5,5};
     pdl *p = new_pdl(PDL_F,dims,3);
     PDL_Float *dataf = (PDL_Float *) p->data;
     PDL_Indx i; /* dimensions might be 64bits */
 
     for (i=0;i<5*5*5;i++)
       dataf[i] = i; /* the data must be initialized ! */
     return p;
   }
 
=head2 Wrapping your own data into an ndarray
 
Sometimes you obtain a chunk of data from another
source, for example an image processing library, etc.
All you want to do in that case is wrap your data
into an ndarray struct at the C level. Examples using this approach
can be found in the IO modules (where FastRaw and FlexRaw
use it for mmapped access) and the Gimp Perl module (that
uses it to wrap Gimp pixel regions into ndarrays).
The following script demonstrates a simple example:
 
   use PDL::LiteF;
   use PDL::Core::Dev;
   use PDL::Graphics::PGPLOT;
 
   $y = mkndarray();
 
   print $y->info,"\n";
 
   imag1 $y;
 
   use Inline with => 'PDL';
   use Inline C;
   Inline->init;
 
   __DATA__
 
   __C__
 
   /* wrap a user supplied chunk of data into an ndarray
    * You must specify the dimensions (dims,ndims) and 
    * the datatype (constants for the datatypes are declared
    * in pdl.h; e.g. PDL_B for byte type, etc)
    *
    * when the created ndarray 'npdl' is destroyed on the
    * Perl side the function passed as the 'delete_magic'
    * parameter will be called with the pointer to the pdl structure
    * and the 'delparam' argument.
    * This gives you an opportunity to perform any clean up
    * that is necessary. For example, you might have to
    * explicitly call a function to free the resources
    * associated with your data pointer.
    * At the very least 'delete_magic' should zero the ndarray's data pointer:
    * 
    *     void delete_mydata(pdl* pdl, int param)
    *     {
    *       pdl->data = 0;
    *     }
    *     pdl *p = pdl_wrap(mydata, PDL_B, dims, ndims, delete_mydata,0);
    *
    * pdl_wrap returns the pointer to the pdl
    * that was created.
    */
   typedef void (*DelMagic)(pdl *, int param);
   static void default_magic(pdl *p, int pa) { p->data = 0; }
   static pdl* pdl_wrap(void *data, int datatype, PDL_Indx dims[],
                        int ndims, DelMagic delete_magic, int delparam)
   {
     pdl* npdl = PDL->pdlnew(); /* get the empty container */
 
     PDL->setdims(npdl,dims,ndims); /* set dims      */
     npdl->datatype = datatype;     /* and data type */
     npdl->data = data;             /* point it to your data */
     /* make sure the core doesn't meddle with your data */
     npdl->state |= PDL_DONTTOUCHDATA | PDL_ALLOCATED;
     if (delete_magic != NULL)
       PDL->add_deletedata_magic(npdl, delete_magic, delparam);
     else
       PDL->add_deletedata_magic(npdl, default_magic, 0);
     return npdl;
   }
 
   #define SZ 256
   /* a really silly function that makes a ramp image
    * in reality this could be an opaque function
    * in some library that you are using
    */
   static PDL_Byte* mkramp(void)
   {
     PDL_Byte *data;
     int i; /* should use PDL_Indx to support 64bit pdl indexing */
 
     if ((data = malloc(SZ*SZ*sizeof(PDL_Byte))) == NULL)
       croak("mkramp: Couldn't allocate memory");
     for (i=0;i<SZ*SZ;i++)
       data[i] = i % SZ;
 
     return data;
   }
 
   /* this function takes care of the required clean-up */
   static void delete_myramp(pdl* p, int param)
   {
     if (p->data)
       free(p->data);
     p->data = 0;
   }
 
   pdl* mkndarray()
   {
     PDL_Indx dims[] = {SZ,SZ};
     pdl *p;
 
     p = pdl_wrap((void *) mkramp(), PDL_B, dims, 2, 
                  delete_myramp,0); /* the delparam is abitrarily set to 0 */
     return p;
   }
 
=head1 The gory details
 
=head2 The Core struct -- getting at PDL core routines at runtime
 
PDL uses a technique similar to that employed by the Tk modules
to let other modules use its core routines. A pointer to all
shared core PDL routines is stored in the C<$PDL::SHARE> variable.
XS code should get hold of this pointer at boot time so that
the rest of the C/XS code can then use that pointer for access
at run time. This initial loading of the pointer is most easily
achieved using the functions C<PDL_AUTO_INCLUDE> and C<PDL_BOOT>
that are defined and exported by C<PDL::Core::Dev>. Typical usage
with the Inline module has already been demonstrated:
 
   use Inline with => 'PDL';
 
In earlier versions of C<Inline>, this was achieved like this:
 
   use Inline C => Config =>
     INC           => &PDL_INCLUDE,
     TYPEMAPS      => &PDL_TYPEMAP,
     AUTO_INCLUDE  => &PDL_AUTO_INCLUDE, # declarations
     BOOT          => &PDL_BOOT;         # code for the XS boot section
 
The code returned by C<PDL_AUTO_INCLUDE> makes sure that F<pdlcore.h>
is included and declares the static variables to hold the pointer to
the C<Core> struct. It looks something like this:
 
   print PDL_AUTO_INCLUDE;
 
 #include <pdlcore.h>
 static Core* PDL; /* Structure holds core C functions */
 static SV* CoreSV;       /* Gets pointer to Perl var holding core structure */
 
The code returned by C<PDL_BOOT> retrieves the C<$PDL::SHARE> variable
and initializes the pointer to the C<Core> struct. For those who know
their way around the Perl API here is the code:
 
   perl_require_pv ("PDL/Core.pm"); /* make sure PDL::Core is loaded */
#ifndef aTHX_
#define aTHX_
#endif
   if (SvTRUE (ERRSV)) Perl_croak(aTHX_ "%s",SvPV_nolen (ERRSV));
   CoreSV = perl_get_sv("PDL::SHARE",FALSE);  /* SV* value */
   if (CoreSV==NULL)
     Perl_croak(aTHX_ "We require the PDL::Core module, which was not found");
   PDL = INT2PTR(Core*,SvIV( CoreSV ));  /* Core* value */
   if (PDL->Version != PDL_CORE_VERSION)
     Perl_croak(aTHX_ "[PDL->Version: \%d PDL_CORE_VERSION: \%d XS_VERSION: \%s] The code needs to be recompiled against the newly installed PDL", PDL->Version, PDL_CORE_VERSION, XS_VERSION);
 
The C<Core> struct contains version info to ensure that the structure defined
in F<pdlcore.h> really corresponds to the one obtained at runtime. The code
above tests for this
 
   if (PDL->Version != PDL_CORE_VERSION)
     ....
 
For more information on the Core struct see L<PDL::Internals>.
 
With these preparations your code can now access the
core routines as already shown in some of the examples above, e.g.
 
  pdl *p = PDL->pdlnew();
 
By default the C variable named C<PDL> is used to hold the pointer to the
C<Core> struct. If that is (for whichever reason) a problem you can
explicitly specify a name for the variable with the C<PDL_AUTO_INCLUDE>
and the C<PDL_BOOT> routines:
 
   use Inline C => Config =>
     INC           => &PDL_INCLUDE,
     TYPEMAPS      => &PDL_TYPEMAP,
     AUTO_INCLUDE  => &PDL_AUTO_INCLUDE 'PDL_Corep',
     BOOT          => &PDL_BOOT 'PDL_Corep';
 
Make sure you use the same identifier with C<PDL_AUTO_INCLUDE>
and C<PDL_BOOT> and use that same identifier in your own code.
E.g., continuing from the example above:
 
  pdl *p = PDL_Corep->pdlnew();
 
=head2 Some selected core routines explained
 
The full definition of the C<Core> struct can be found in the file
F<pdlcore.h>. In the following the most frequently used member
functions of this struct are briefly explained.
 
=over 5
 
=item *
 
C<pdl *SvPDLV(SV *sv)>
 
=item *
 
C<pdl *SetSV_PDL(SV *sv, pdl *it)>
 
=item *
 
C<pdl *pdlnew()>
 
C<pdlnew> returns an empty pdl object that needs further initialization
to turn it into a proper ndarray. Example:
 
  pdl *p = PDL->pdlnew();
  PDL->setdims(p,dims,ndims);
  p->datatype = PDL_B;
 
=item *
 
C<pdl *null()>
 
=item *
 
C<SV *copy(pdl* p, char* )>
 
=item *
 
C<void *smalloc(STRLEN nbytes)>
 
=item *
 
C<int howbig(int pdl_datatype)>
 
=item *
 
C<void add_deletedata_magic(pdl *p, void (*func)(pdl*, int), int param)>
 
=item *
 
C<void allocdata(pdl *p)>
 
=item *
 
C<void make_physical(pdl *p)>
 
=item *
 
C<void make_physdims(pdl *p)>
 
=item *
 
C<void make_physvaffine(pdl *p)>
 
=item *
 
C<void qsort_X(PDL_Xtype *data, PDL_Indx a, PDL_Indx b)> and
C<void qsort_ind_X(PDL_Xtype *data, PDL_Indx *ix, PDL_Indx a, PDL_Indx b)>
 
where X is one of B,S,U,L,F,D and Xtype is one of Byte, Short, Ushort,
Long, Float or Double.  PDL_Indx is the C integer type corresponding to
appropriate indexing size for the perl configuration (ivsize and ivtype).
It can be either 'long' or 'long long' depending on whether your perl
is 32bit or 64bit enabled.
 
=item *
 
C<void pdl_barf(const char* pat,...)> and
C<void pdl_warn(const char* pat,...)>
 
These are C-code equivalents of C<barf> and C<warn>. They include special handling of error or warning
messages during pthreading (i.e. processor multi-threading) that defer the messages until after pthreading
is completed. When pthreading is complete, perl's C<barf> or C<warn> is called with the deferred messages. This
is needed to keep from calling perl's C<barf> or C<warn> during pthreading, which can cause segfaults. 
 
Note that C<barf> and C<warn> have been redefined (using c-preprocessor macros) in pdlcore.h to C<< PDL->barf >>
and C<< PDL->warn >>. This is to keep any XS or PP code from calling perl's C<barf> or C<warn> directly, which can
cause segfaults during pthreading.
 
See L<PDL::ParallelCPU> for more information on pthreading.
 
=back
 
=cut
 
# ones that are not clear:
# safe_indterm
# converttypei_new
# converttype
# get_convertedpdl
# affine_new
# make_trans_mutual
# make_now
# get
# get_offs
# put_offs
# setdims_careful
# destroy
# twod
# grow
# reallocdims
# reallocthreadids
# resize_defaultincs

 
=head1 SEE ALSO
 
L<PDL>
 
L<Inline>
 
=head2 Handy macros from pdl.h
 
Some of the C API functions return C<PDL_Anyval> C type which
is a structure and therefore requires special handling.
 
You might want to use for example C<get_pdl_badvalue> function:
 
 /* THIS DOES NOT WORK! (although it did in older PDL) */
 if( PDL->get_pdl_badvalue(a) == 0 )  { ... }
 
 /* THIS IS CORRECT */
 double bad_a;
 ANYVAL_TO_CTYPE(bad_a, double, PDL->get_pdl_badvalue(a));
 if( bad_a == 0 ) { ... }
 
As of PDL 2.014, in F<pdl.h> there are the following macros for handling
PDL_Anyval from C code:
 
 ANYVAL_FROM_CTYPE(out_anyval, out_anyval_type, in_variable)
 ANYVAL_TO_CTYPE(out_variable, out_ctype, in_anyval)
 ANYVAL_EQ_ANYVAL(x, y)
 
As of PDL 2.039 there is:
 
 ANYVAL_ISNAN(anyval)
 
As of PDL 2.040 (the additional parameters are to detect the badflag,
and handle caching the bad value for efficiency):
 
 ANYVAL_ISBAD(in_anyval, pdl, badval)
 
As of PDL 2.048, in F<pdlperl.h> there are:
 
 ANYVAL_FROM_SV(out_anyval, in_SV, use_undefval, forced_type)
 ANYVAL_TO_SV(out_SV, in_anyval)
 
Because these are used in the PDL F<typemap.pdl>, you will need to
include F<pdlperl.h> in any XS file with functions that take or
return a C<PDL_Anyval>.
 
=head1 BUGS
 
This manpage is still under development.
Feedback and corrections are welcome.
 
 
=head1 COPYRIGHT
 
Copyright 2013 Chris Marshall (chm@cpan.org).
 
Copyright 2010 Christian Soeller (c.soeller@auckland.ac.nz).
You can distribute and/or modify this document under the same
terms as the current Perl license.
 
See: http://dev.perl.org/licenses/
 
=cut