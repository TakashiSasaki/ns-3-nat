/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
//
// Copyright (c) 2006 Georgia Tech Research Corporation
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation;
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// Author: Rajib Bhattacharjea<raj.b@gatech.edu>
// Author: Hadi Arbabi<marbabi@cs.odu.edu>
//

#include <iostream>

#include <math.h>
#include <stdlib.h>
#include <sys/time.h>			// for gettimeofday
#include <unistd.h>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>       
#include <sstream>


#include "assert.h"
#include "config.h"
#include "integer.h"
#include "random-variable.h"
#include "rng-stream.h"
#include "fatal-error.h"

using namespace std;

namespace ns3{

//-----------------------------------------------------------------------------
// Seed Manager
//-----------------------------------------------------------------------------

uint32_t SeedManager::GetSeed()
{
  uint32_t s[6];
  RngStream::GetPackageSeed (s);
  NS_ASSERT(
              s[0] == s[1] &&
              s[0] == s[2] &&
              s[0] == s[3] &&
              s[0] == s[4] &&
              s[0] == s[5]    
            );
  return s[0];
}

void SeedManager::SetSeed(uint32_t seed)
{
  Config::SetGlobal("RngSeed", IntegerValue(seed));
}

void SeedManager::SetRun(uint32_t run)
{
  Config::SetGlobal("RngRun", IntegerValue(run));
}

uint32_t SeedManager::GetRun()
{
  return RngStream::GetPackageRun ();
}

bool SeedManager::CheckSeed (uint32_t seed)
{
  return RngStream::CheckSeed(seed);
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// RandomVariableBase methods


class RandomVariableBase 
{
public:
  RandomVariableBase ();
  RandomVariableBase (const RandomVariableBase &o);
  virtual ~RandomVariableBase();
  virtual double  GetValue() = 0;
  virtual uint32_t GetInteger();
  virtual RandomVariableBase*   Copy(void) const = 0;

protected:
  RngStream* m_generator;  //underlying generator being wrapped
};

RandomVariableBase::RandomVariableBase() 
  : m_generator(NULL)
{
}

RandomVariableBase::RandomVariableBase(const RandomVariableBase& r)
  :m_generator(0)
{
  if (r.m_generator)
    {
      m_generator = new RngStream(*r.m_generator);
    }
}

RandomVariableBase::~RandomVariableBase()
{
  delete m_generator;
}

uint32_t RandomVariableBase::GetInteger() 
{
  return (uint32_t)GetValue();
}

//-------------------------------------------------------

RandomVariable::RandomVariable()
  : m_variable (0)
{}
RandomVariable::RandomVariable(const RandomVariable&o)
  : m_variable (o.m_variable->Copy ())
{}
RandomVariable::RandomVariable (const RandomVariableBase &variable)
  : m_variable (variable.Copy ())
{}
RandomVariable &
RandomVariable::operator = (const RandomVariable &o)
{
  if (&o == this)
    {
      return *this;
    }
  delete m_variable;
  m_variable = o.m_variable->Copy ();
  return *this;
}
RandomVariable::~RandomVariable()
{
  delete m_variable;
}
double  
RandomVariable::GetValue (void) const
{
  return m_variable->GetValue ();
}

uint32_t 
RandomVariable::GetInteger (void) const
{
  return m_variable->GetInteger ();
}

RandomVariableBase *
RandomVariable::Peek (void) const
{
  return m_variable;
}


ATTRIBUTE_VALUE_IMPLEMENT (RandomVariable);
ATTRIBUTE_CHECKER_IMPLEMENT (RandomVariable);

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// UniformVariableImpl

class UniformVariableImpl : public RandomVariableBase {
public:
  /**
   * Creates a uniform random number generator in the
   * range [0.0 .. 1.0).
   */
  UniformVariableImpl();

  /**
   * Creates a uniform random number generator with the specified range
   * \param s Low end of the range
   * \param l High end of the range
   */
  UniformVariableImpl(double s, double l);

  UniformVariableImpl(const UniformVariableImpl& c);

  double GetMin (void) const;
  double GetMax (void) const;
  
  /**
   * \return A value between low and high values specified by the constructor
   */
  virtual double GetValue();

  /**
   * \return A value between low and high values specified by parameters
   */
  virtual double GetValue(double s, double l);
  
  virtual RandomVariableBase*  Copy(void) const;

private:
  double m_min;
  double m_max;
};

UniformVariableImpl::UniformVariableImpl() 
  : m_min(0), m_max(1.0) { }
  
UniformVariableImpl::UniformVariableImpl(double s, double l) 
  : m_min(s), m_max(l) { }

UniformVariableImpl::UniformVariableImpl(const UniformVariableImpl& c) 
  : RandomVariableBase(c), m_min(c.m_min), m_max(c.m_max) { }

double 
UniformVariableImpl::GetMin (void) const
{
  return m_min;
}
double 
UniformVariableImpl::GetMax (void) const
{
  return m_max;
}


double UniformVariableImpl::GetValue()
{
  if(!m_generator)
    {
      m_generator = new RngStream();
    }
  return m_min + m_generator->RandU01() * (m_max - m_min);
}

double UniformVariableImpl::GetValue(double s, double l) 
{
  if(!m_generator)
    {
      m_generator = new RngStream();
    }
    return s + m_generator->RandU01() * (l-s); 
}

RandomVariableBase* UniformVariableImpl::Copy() const
{
  return new UniformVariableImpl(*this);
}

UniformVariable::UniformVariable()
  : RandomVariable (UniformVariableImpl ())
{}
UniformVariable::UniformVariable(double s, double l)
  : RandomVariable (UniformVariableImpl (s, l))
{}

double UniformVariable::GetValue()
{
  return Peek()->GetValue();
}

double UniformVariable::GetValue(double s, double l)
{
  return ((UniformVariableImpl*)Peek())->GetValue(s,l);
}


//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// ConstantVariableImpl methods

class ConstantVariableImpl : public RandomVariableBase { 

public:
  /**
   * Construct a ConstantVariableImpl RNG that returns zero every sample
   */
  ConstantVariableImpl();
  
  /**
   * Construct a ConstantVariableImpl RNG that returns the specified value
   * every sample.
   * \param c Unchanging value for this RNG.
   */
  ConstantVariableImpl(double c);


  ConstantVariableImpl(const ConstantVariableImpl& c) ;

  /**
   * \brief Specify a new constant RNG for this generator.
   * \param c New constant value for this RNG.
   */
  void    NewConstant(double c);

  /**
   * \return The constant value specified
   */
  virtual double  GetValue();
  virtual uint32_t GetInteger();
  virtual RandomVariableBase*   Copy(void) const;
private:
  double m_const;
};

ConstantVariableImpl::ConstantVariableImpl() 
  : m_const(0) { }

ConstantVariableImpl::ConstantVariableImpl(double c) 
  : m_const(c) { };
  
ConstantVariableImpl::ConstantVariableImpl(const ConstantVariableImpl& c) 
  : RandomVariableBase(c), m_const(c.m_const) { }

void ConstantVariableImpl::NewConstant(double c) 
  { m_const = c;}
  
double ConstantVariableImpl::GetValue()
{
  return m_const;
}

uint32_t ConstantVariableImpl::GetInteger()
{
  return (uint32_t)m_const;
}

RandomVariableBase* ConstantVariableImpl::Copy() const
{
  return new ConstantVariableImpl(*this);
}

ConstantVariable::ConstantVariable()
  : RandomVariable (ConstantVariableImpl ())
{}
ConstantVariable::ConstantVariable(double c)
  : RandomVariable (ConstantVariableImpl (c))
{}
void 
ConstantVariable::SetConstant(double c)
{
  *this = ConstantVariable (c);
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// SequentialVariableImpl methods


class SequentialVariableImpl : public RandomVariableBase {

public:
  /**
   * \brief Constructor for the SequentialVariableImpl RNG.
   *
   * The four parameters define the sequence.  For example
   * SequentialVariableImpl(0,5,1,2) creates a RNG that has the sequence
   * 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 0, 0 ...
   * \param f First value of the sequence.
   * \param l One more than the last value of the sequence.
   * \param i Increment between sequence values
   * \param c Number of times each member of the sequence is repeated
   */
  SequentialVariableImpl(double f, double l, double i = 1, uint32_t c = 1);

  /**
   * \brief Constructor for the SequentialVariableImpl RNG.
   *
   * Differs from the first only in that the increment parameter is a
   * random variable
   * \param f First value of the sequence.
   * \param l One more than the last value of the sequence.
   * \param i Reference to a RandomVariableBase for the sequence increment
   * \param c Number of times each member of the sequence is repeated
   */
  SequentialVariableImpl(double f, double l, const RandomVariable& i, uint32_t c = 1);

  SequentialVariableImpl(const SequentialVariableImpl& c);
  
  ~SequentialVariableImpl();
  /**
   * \return The next value in the Sequence
   */
  virtual double GetValue();
  virtual RandomVariableBase*  Copy(void) const;
private:
  double m_min;
  double m_max;
  RandomVariable  m_increment;
  uint32_t  m_consecutive;
  double m_current;
  uint32_t  m_currentConsecutive;
};

SequentialVariableImpl::SequentialVariableImpl(double f, double l, double i, uint32_t c)
  : m_min(f), m_max(l), m_increment(ConstantVariable(i)), m_consecutive(c),
    m_current(f), m_currentConsecutive(0)
{}

SequentialVariableImpl::SequentialVariableImpl(double f, double l, const RandomVariable& i, uint32_t c)
  : m_min(f), m_max(l), m_increment(i), m_consecutive(c),
    m_current(f), m_currentConsecutive(0)
{}

SequentialVariableImpl::SequentialVariableImpl(const SequentialVariableImpl& c)
  : RandomVariableBase(c), m_min(c.m_min), m_max(c.m_max),
    m_increment(c.m_increment), m_consecutive(c.m_consecutive),
    m_current(c.m_current), m_currentConsecutive(c.m_currentConsecutive)
{}

SequentialVariableImpl::~SequentialVariableImpl()
{}

double SequentialVariableImpl::GetValue()
{ // Return a sequential series of values
  double r = m_current;
  if (++m_currentConsecutive == m_consecutive)
    { // Time to advance to next
      m_currentConsecutive = 0;
      m_current += m_increment.GetValue();
      if (m_current >= m_max)
        m_current = m_min + (m_current - m_max);
    }
  return r;
}

RandomVariableBase* SequentialVariableImpl::Copy() const
{
  return new SequentialVariableImpl(*this);
}

SequentialVariable::SequentialVariable(double f, double l, double i, uint32_t c)
  : RandomVariable (SequentialVariableImpl (f, l, i, c))
{}
SequentialVariable::SequentialVariable(double f, double l, const RandomVariable& i, uint32_t c)
  : RandomVariable (SequentialVariableImpl (f, l, i, c))
{}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// ExponentialVariableImpl methods

class ExponentialVariableImpl : public RandomVariableBase { 
public:
  /**
   * Constructs an exponential random variable  with a mean
   * value of 1.0.
   */
  ExponentialVariableImpl();

  /**
   * \brief Constructs an exponential random variable with a specified mean
   * \param m Mean value for the random variable
   */
  explicit ExponentialVariableImpl(double m);

  /**
   * \brief Constructs an exponential random variable with spefified
   * \brief mean and upper limit.
   *
   * Since exponential distributions can theoretically return unbounded values,
   * it is sometimes useful to specify a fixed upper limit.  Note however when
   * the upper limit is specified, the true mean of the distribution is 
   * slightly smaller than the mean value specified.
   * \param m Mean value of the random variable
   * \param b Upper bound on returned values
   */
  ExponentialVariableImpl(double m, double b);

  ExponentialVariableImpl(const ExponentialVariableImpl& c);
  
  /**
   * \return A random value from this exponential distribution
   */
  virtual double GetValue();
  virtual RandomVariableBase* Copy(void) const;

private:
  double m_mean;  // Mean value of RV
  double m_bound; // Upper bound on value (if non-zero)
};

ExponentialVariableImpl::ExponentialVariableImpl() 
  : m_mean(1.0), m_bound(0) { }
  
ExponentialVariableImpl::ExponentialVariableImpl(double m) 
  : m_mean(m), m_bound(0) { }
  
ExponentialVariableImpl::ExponentialVariableImpl(double m, double b) 
  : m_mean(m), m_bound(b) { }
  
ExponentialVariableImpl::ExponentialVariableImpl(const ExponentialVariableImpl& c) 
  : RandomVariableBase(c), m_mean(c.m_mean), m_bound(c.m_bound) { }

double ExponentialVariableImpl::GetValue()
{
  if(!m_generator)
    {
      m_generator = new RngStream();
    }
  while(1)
    {
      double r = -m_mean*log(m_generator->RandU01());
      if (m_bound == 0 || r <= m_bound) return r;
      //otherwise, try again
    }
}

RandomVariableBase* ExponentialVariableImpl::Copy() const
{
  return new ExponentialVariableImpl(*this);
}

ExponentialVariable::ExponentialVariable()
  : RandomVariable (ExponentialVariableImpl ())
{}
ExponentialVariable::ExponentialVariable(double m)
  : RandomVariable (ExponentialVariableImpl (m))
{}
ExponentialVariable::ExponentialVariable(double m, double b)
  : RandomVariable (ExponentialVariableImpl (m, b))
{}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// ParetoVariableImpl methods
class ParetoVariableImpl : public RandomVariableBase {
public:
  /**
   * Constructs a pareto random variable with a mean of 1 and a shape
   * parameter of 1.5
   */
  ParetoVariableImpl();

  /**
   * Constructs a pareto random variable with specified mean and shape
   * parameter of 1.5
   * \param m Mean value of the distribution
   */
  explicit ParetoVariableImpl(double m);

  /**
   * Constructs a pareto random variable with the specified mean value and
   * shape parameter.
   * \param m Mean value of the distribution
   * \param s Shape parameter for the distribution
   */
  ParetoVariableImpl(double m, double s);

  /**
   * \brief Constructs a pareto random variable with the specified mean
   * \brief value, shape (alpha), and upper bound.
   *
   * Since pareto distributions can theoretically return unbounded values,
   * it is sometimes useful to specify a fixed upper limit.  Note however
   * when the upper limit is specified, the true mean of the distribution
   * is slightly smaller than the mean value specified.
   * \param m Mean value
   * \param s Shape parameter
   * \param b Upper limit on returned values
   */
  ParetoVariableImpl(double m, double s, double b);

  ParetoVariableImpl(const ParetoVariableImpl& c);
  
  /**
   * \return A random value from this Pareto distribution
   */
  virtual double GetValue();
  virtual RandomVariableBase* Copy() const;

private:
  double m_mean;  // Mean value of RV
  double m_shape; // Shape parameter
  double m_bound; // Upper bound on value (if non-zero)
};

ParetoVariableImpl::ParetoVariableImpl() 
  : m_mean(1.0), m_shape(1.5), m_bound(0) { }

ParetoVariableImpl::ParetoVariableImpl(double m) 
  : m_mean(m), m_shape(1.5), m_bound(0) { }

ParetoVariableImpl::ParetoVariableImpl(double m, double s) 
    : m_mean(m), m_shape(s), m_bound(0) { }

ParetoVariableImpl::ParetoVariableImpl(double m, double s, double b) 
  : m_mean(m), m_shape(s), m_bound(b) { }

ParetoVariableImpl::ParetoVariableImpl(const ParetoVariableImpl& c) 
  : RandomVariableBase(c), m_mean(c.m_mean), m_shape(c.m_shape), 
    m_bound(c.m_bound) { }

double ParetoVariableImpl::GetValue()
{
  if(!m_generator)
    {
      m_generator = new RngStream();
    }
  double scale = m_mean * ( m_shape - 1.0) / m_shape;
  while(1)
    {
      double r = (scale * ( 1.0 / pow(m_generator->RandU01(), 1.0 / m_shape)));
      if (m_bound == 0 || r <= m_bound) return r;
      //otherwise, try again
    }
}

RandomVariableBase* ParetoVariableImpl::Copy() const
{
  return new ParetoVariableImpl(*this);
}

ParetoVariable::ParetoVariable ()
  : RandomVariable (ParetoVariableImpl ())
{}
ParetoVariable::ParetoVariable(double m)
  : RandomVariable (ParetoVariableImpl (m))
{}
ParetoVariable::ParetoVariable(double m, double s)
  : RandomVariable (ParetoVariableImpl (m, s))
{}
ParetoVariable::ParetoVariable(double m, double s, double b)
  : RandomVariable (ParetoVariableImpl (m, s, b))
{}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// WeibullVariableImpl methods

class WeibullVariableImpl : public RandomVariableBase {
public:
  /**
   * Constructs a weibull random variable  with a mean
   * value of 1.0 and a shape (alpha) parameter of 1
   */
  WeibullVariableImpl();


  /**
   * Constructs a weibull random variable with the specified mean
   * value and a shape (alpha) parameter of 1.5.
   * \param m mean value of the distribution
   */
   WeibullVariableImpl(double m) ;

  /**
   * Constructs a weibull random variable with the specified mean
   * value and a shape (alpha).
   * \param m Mean value for the distribution.
   * \param s Shape (alpha) parameter for the distribution.
   */
  WeibullVariableImpl(double m, double s);

   /**
   * \brief Constructs a weibull random variable with the specified mean
   * \brief value, shape (alpha), and upper bound.
   * Since WeibullVariableImpl distributions can theoretically return unbounded values,
   * it is sometimes usefull to specify a fixed upper limit.  Note however
   * that when the upper limit is specified, the true mean of the distribution
   * is slightly smaller than the mean value specified.
   * \param m Mean value for the distribution.
   * \param s Shape (alpha) parameter for the distribution.
   * \param b Upper limit on returned values
   */
  WeibullVariableImpl(double m, double s, double b);

  WeibullVariableImpl(const WeibullVariableImpl& c);
  
  /**
   * \return A random value from this Weibull distribution
   */
  virtual double GetValue();
  virtual RandomVariableBase* Copy(void) const;

private:
  double m_mean;  // Mean value of RV
  double m_alpha; // Shape parameter
  double m_bound; // Upper bound on value (if non-zero)
};

WeibullVariableImpl::WeibullVariableImpl() : m_mean(1.0), m_alpha(1), m_bound(0) { }
WeibullVariableImpl::WeibullVariableImpl(double m) 
  : m_mean(m), m_alpha(1), m_bound(0) { }
WeibullVariableImpl::WeibullVariableImpl(double m, double s) 
  : m_mean(m), m_alpha(s), m_bound(0) { }
WeibullVariableImpl::WeibullVariableImpl(double m, double s, double b) 
  : m_mean(m), m_alpha(s), m_bound(b) { };
WeibullVariableImpl::WeibullVariableImpl(const WeibullVariableImpl& c) 
  : RandomVariableBase(c), m_mean(c.m_mean), m_alpha(c.m_alpha),
    m_bound(c.m_bound) { }

double WeibullVariableImpl::GetValue()
{
  if(!m_generator)
    {
      m_generator = new RngStream();
    }
  double exponent = 1.0 / m_alpha;
  while(1)
    {
      double r = m_mean * pow( -log(m_generator->RandU01()), exponent);
      if (m_bound == 0 || r <= m_bound) return r;
      //otherwise, try again
    }
}

RandomVariableBase* WeibullVariableImpl::Copy() const
{
  return new WeibullVariableImpl(*this);
}

WeibullVariable::WeibullVariable()
  : RandomVariable (WeibullVariableImpl ())
{}
WeibullVariable::WeibullVariable(double m)
  : RandomVariable (WeibullVariableImpl (m))
{}
WeibullVariable::WeibullVariable(double m, double s)
  : RandomVariable (WeibullVariableImpl (m, s))
{}
WeibullVariable::WeibullVariable(double m, double s, double b)
  : RandomVariable (WeibullVariableImpl (m, s, b))
{}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// NormalVariableImpl methods

class NormalVariableImpl : public RandomVariableBase { // Normally Distributed random var

public:
   static const double INFINITE_VALUE;
  /**
   * Constructs an normal random variable  with a mean
   * value of 0 and variance of 1.
   */ 
  NormalVariableImpl();

  /**
   * \brief Construct a normal random variable with specified mean and variance
   * \param m Mean value
   * \param v Variance
   * \param b Bound.  The NormalVariableImpl is bounded within +-bound of the mean.
   */ 
  NormalVariableImpl(double m, double v, double b = INFINITE_VALUE);

  NormalVariableImpl(const NormalVariableImpl& c);
  
  /**
   * \return A value from this normal distribution
   */
  virtual double GetValue();
  virtual RandomVariableBase* Copy(void) const;

private:
  double m_mean;      // Mean value of RV
  double m_variance;  // Mean value of RV
  double m_bound;     // Bound on value's difference from the mean (absolute value)
  bool   m_nextValid; // True if next valid
  double m_next;      // The algorithm produces two values at a time
  static bool   m_static_nextValid;
  static double m_static_next;
};

bool         NormalVariableImpl::m_static_nextValid = false;
double       NormalVariableImpl::m_static_next;
const double NormalVariableImpl::INFINITE_VALUE = 1e307;

NormalVariableImpl::NormalVariableImpl() 
  : m_mean(0.0), m_variance(1.0), m_bound(INFINITE_VALUE), m_nextValid(false){}

NormalVariableImpl::NormalVariableImpl(double m, double v, double b/*=INFINITE_VALUE*/)
  : m_mean(m), m_variance(v), m_bound(b), m_nextValid(false) { }

NormalVariableImpl::NormalVariableImpl(const NormalVariableImpl& c)
  : RandomVariableBase(c), m_mean(c.m_mean), m_variance(c.m_variance),
    m_bound(c.m_bound) { }

double NormalVariableImpl::GetValue()
{
  if(!m_generator)
    {
      m_generator = new RngStream();
    }
  if (m_nextValid)
    { // use previously generated
      m_nextValid = false;
      return m_next;
    }
  while(1)
    { // See Simulation Modeling and Analysis p. 466 (Averill Law)
      // for algorithm; basically a Box-Muller transform:
      // http://en.wikipedia.org/wiki/Box-Muller_transform
      double u1 = m_generator->RandU01();
      double u2 = m_generator->RandU01();;
      double v1 = 2 * u1 - 1;
      double v2 = 2 * u2 - 1;
      double w = v1 * v1 + v2 * v2;
      if (w <= 1.0)
        { // Got good pair
          double y = sqrt((-2 * log(w))/w);
          m_next = m_mean + v2 * y * sqrt(m_variance);
          //if next is in bounds, it is valid
          m_nextValid = fabs(m_next-m_mean) <= m_bound;
          double x1 = m_mean + v1 * y * sqrt(m_variance);
          //if x1 is in bounds, return it
          if (fabs(x1-m_mean) <= m_bound)
            {
              return x1;
            }
          //otherwise try and return m_next if it is valid
          else if (m_nextValid)
	    {
	      m_nextValid = false;
	      return m_next;
	    }
          //otherwise, just run this loop again
        }
    }
}

RandomVariableBase* NormalVariableImpl::Copy() const
{
  return new NormalVariableImpl(*this);
}

NormalVariable::NormalVariable()
  : RandomVariable (NormalVariableImpl ())
{}
NormalVariable::NormalVariable(double m, double v)
  : RandomVariable (NormalVariableImpl (m, v))
{}
NormalVariable::NormalVariable(double m, double v, double b)
  : RandomVariable (NormalVariableImpl (m, v, b))
{}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
class EmpiricalVariableImpl : public RandomVariableBase {
public:
  /**
   * Constructor for the EmpiricalVariableImpl random variables.
   */
  explicit EmpiricalVariableImpl();

  virtual ~EmpiricalVariableImpl();
  EmpiricalVariableImpl(const EmpiricalVariableImpl& c);
  /**
   * \return A value from this empirical distribution
   */
  virtual double GetValue();
  virtual RandomVariableBase* Copy(void) const;
  /**
   * \brief Specifies a point in the empirical distribution
   * \param v The function value for this point
   * \param c Probability that the function is less than or equal to v
   */
  virtual void CDF(double v, double c);  // Value, prob <= Value

private:
  class ValueCDF {
  public:
    ValueCDF();
    ValueCDF(double v, double c);
    ValueCDF(const ValueCDF& c);
    double value;
    double    cdf;
  };
  virtual void Validate();  // Insure non-decreasing emiprical values
  virtual double Interpolate(double, double, double, double, double);
  bool validated; // True if non-decreasing validated
  std::vector<ValueCDF> emp;       // Empicical CDF
};


// ValueCDF methods
EmpiricalVariableImpl::ValueCDF::ValueCDF() 
  : value(0.0), cdf(0.0){ }
EmpiricalVariableImpl::ValueCDF::ValueCDF(double v, double c) 
  : value(v), cdf(c) { }
EmpiricalVariableImpl::ValueCDF::ValueCDF(const ValueCDF& c) 
  : value(c.value), cdf(c.cdf) { }

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// EmpiricalVariableImpl methods
EmpiricalVariableImpl::EmpiricalVariableImpl() 
  : validated(false) { }

EmpiricalVariableImpl::EmpiricalVariableImpl(const EmpiricalVariableImpl& c)
  : RandomVariableBase(c), validated(c.validated), emp(c.emp) { }

EmpiricalVariableImpl::~EmpiricalVariableImpl() { }

double EmpiricalVariableImpl::GetValue()
{ // Return a value from the empirical distribution
  // This code based (loosely) on code by Bruce Mah (Thanks Bruce!)
  if(!m_generator)
    {
      m_generator = new RngStream();
    }
  if (emp.size() == 0) 
    {
      return 0.0; // HuH? No empirical data
    }
  if (!validated) 
    {
      Validate();      // Insure in non-decreasing
    }
  double r = m_generator->RandU01();
  if (r <= emp.front().cdf)
    {
      return emp.front().value; // Less than first
    }
  if (r >= emp.back().cdf) 
    { 
      return emp.back().value;  // Greater than last
    }
  // Binary search
  std::vector<ValueCDF>::size_type bottom = 0;
  std::vector<ValueCDF>::size_type top = emp.size() - 1;
  while(1)
    {
      std::vector<ValueCDF>::size_type c = (top + bottom) / 2;
      if (r >= emp[c].cdf && r < emp[c+1].cdf)
        { // Found it
          return Interpolate(emp[c].cdf, emp[c+1].cdf,
                             emp[c].value, emp[c+1].value,
                             r);
        }
      // Not here, adjust bounds
      if (r < emp[c].cdf)
        {
          top    = c - 1;
        }
      else
        {
          bottom = c + 1;
        }
    }
}

RandomVariableBase* EmpiricalVariableImpl::Copy() const
{
  return new EmpiricalVariableImpl(*this);
}

void EmpiricalVariableImpl::CDF(double v, double c)
{ // Add a new empirical datapoint to the empirical cdf
  // NOTE.   These MUST be inserted in non-decreasing order
  emp.push_back(ValueCDF(v, c));
}

void EmpiricalVariableImpl::Validate()
{
  ValueCDF prior;
  for (std::vector<ValueCDF>::size_type i = 0; i < emp.size(); ++i)
    {
      ValueCDF& current = emp[i];
      if (current.value < prior.value || current.cdf < prior.cdf)
        { // Error
          cerr << "Empirical Dist error,"
               << " current value " << current.value
               << " prior value "   << prior.value
               << " current cdf "   << current.cdf
               << " prior cdf "     << prior.cdf << endl;
          NS_FATAL_ERROR("Empirical Dist error");
        }
      prior = current;
    }
  validated = true;
}

double EmpiricalVariableImpl::Interpolate(double c1, double c2,
                                double v1, double v2, double r)
{ // Interpolate random value in range [v1..v2) based on [c1 .. r .. c2)
  return (v1 + ((v2 - v1) / (c2 - c1)) * (r - c1));
}

EmpiricalVariable::EmpiricalVariable()
  : RandomVariable (EmpiricalVariableImpl ())
{}
EmpiricalVariable::EmpiricalVariable (const RandomVariableBase &variable)
  : RandomVariable (variable)
{}
void 
EmpiricalVariable::CDF(double v, double c)
{
  EmpiricalVariableImpl *impl = dynamic_cast<EmpiricalVariableImpl *> (Peek ());
  NS_ASSERT (impl);
  impl->CDF (v, c);
}


//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// IntegerValue EmpiricalVariableImpl methods
class IntEmpiricalVariableImpl : public EmpiricalVariableImpl {
public:

  IntEmpiricalVariableImpl();
  
  virtual RandomVariableBase* Copy(void) const;
  /**
   * \return An integer value from this empirical distribution
   */
  virtual uint32_t GetInteger();
private:
  virtual double Interpolate(double, double, double, double, double);
};


IntEmpiricalVariableImpl::IntEmpiricalVariableImpl() { }

uint32_t IntEmpiricalVariableImpl::GetInteger()
{
  return (uint32_t)GetValue();
}

RandomVariableBase* IntEmpiricalVariableImpl::Copy() const
{
  return new IntEmpiricalVariableImpl(*this);
}

double IntEmpiricalVariableImpl::Interpolate(double c1, double c2,
                                   double v1, double v2, double r)
{ // Interpolate random value in range [v1..v2) based on [c1 .. r .. c2)
  return ceil(v1 + ((v2 - v1) / (c2 - c1)) * (r - c1));
}

IntEmpiricalVariable::IntEmpiricalVariable()
  : EmpiricalVariable (IntEmpiricalVariableImpl ())
{}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// DeterministicVariableImpl
class DeterministicVariableImpl : public RandomVariableBase 
{

public:
  /**
   * \brief Constructor
   *
   * Creates a generator that returns successive elements of the d array
   * on successive calls to ::Value().  Note that the d pointer is copied
   * for use by the generator (shallow-copy), not its contents, so the 
   * contents of the array d points to have to remain unchanged for the use 
   * of DeterministicVariableImpl to be meaningful.
   * \param d Pointer to array of random values to return in sequence
   * \param c Number of values in the array
   */
  explicit DeterministicVariableImpl(double* d, uint32_t c);

  virtual ~DeterministicVariableImpl();
  /**
   * \return The next value in the deterministic sequence
   */
  virtual double GetValue();
  virtual RandomVariableBase* Copy(void) const;
private:
  uint32_t   count;
  uint32_t   next;
  double* data;
};

DeterministicVariableImpl::DeterministicVariableImpl(double* d, uint32_t c)
    : count(c), next(c), data(d)
{ // Nothing else needed
}

DeterministicVariableImpl::~DeterministicVariableImpl() { }
  
double DeterministicVariableImpl::GetValue()
{
  if (next == count) 
    {
      next = 0;
    }
  return data[next++];
}

RandomVariableBase* DeterministicVariableImpl::Copy() const
{
  return new DeterministicVariableImpl(*this);
}

DeterministicVariable::DeterministicVariable(double* d, uint32_t c)
  : RandomVariable (DeterministicVariableImpl (d, c))
{}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// LogNormalVariableImpl
class LogNormalVariableImpl : public RandomVariableBase { 
public:
  /**
   * \param mu mu parameter of the lognormal distribution
   * \param sigma sigma parameter of the lognormal distribution
   */
  LogNormalVariableImpl (double mu, double sigma);

  /**
   * \return A random value from this distribution
   */
  virtual double GetValue ();
  virtual RandomVariableBase* Copy(void) const;

private:
  double m_mu;
  double m_sigma;
};


RandomVariableBase* LogNormalVariableImpl::Copy () const
{
  return new LogNormalVariableImpl (m_mu, m_sigma);
}

LogNormalVariableImpl::LogNormalVariableImpl (double mu, double sigma)
    :m_mu(mu), m_sigma(sigma) 
{
}

// The code from this function was adapted from the GNU Scientific
// Library 1.8:
/* randist/lognormal.c
 * 
 * Copyright (C) 1996, 1997, 1998, 1999, 2000 James Theiler, Brian Gough
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
/* The lognormal distribution has the form 

   p(x) dx = 1/(x * sqrt(2 pi sigma^2)) exp(-(ln(x) - zeta)^2/2 sigma^2) dx

   for x > 0. Lognormal random numbers are the exponentials of
   gaussian random numbers */
double
LogNormalVariableImpl::GetValue ()
{
  if(!m_generator)
    {
      m_generator = new RngStream();
    }
  double u, v, r2, normal, z;

  do
    {
      /* choose x,y in uniform square (-1,-1) to (+1,+1) */

      u = -1 + 2 * m_generator->RandU01 ();
      v = -1 + 2 * m_generator->RandU01 ();

      /* see if it is in the unit circle */
      r2 = u * u + v * v;
    }
  while (r2 > 1.0 || r2 == 0);

  normal = u * sqrt (-2.0 * log (r2) / r2);

  z =  exp (m_sigma * normal + m_mu);

  return z;
}

LogNormalVariable::LogNormalVariable (double mu, double sigma)
  : RandomVariable (LogNormalVariableImpl (mu, sigma))
{}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// TriangularVariableImpl methods
class TriangularVariableImpl : public RandomVariableBase {
public:
  /**
   * Creates a triangle distribution random number generator in the
   * range [0.0 .. 1.0), with mean of 0.5
   */
  TriangularVariableImpl();

  /**
   * Creates a triangle distribution random number generator with the specified
   * range
   * \param s Low end of the range
   * \param l High end of the range
   * \param mean mean of the distribution
   */
  TriangularVariableImpl(double s, double l, double mean);

  TriangularVariableImpl(const TriangularVariableImpl& c);
  
  /**
   * \return A value from this distribution
   */
  virtual double GetValue();
  virtual RandomVariableBase*  Copy(void) const;

private:
  double m_min;
  double m_max;
  double m_mode;  //easier to work with the mode internally instead of the mean
                  //they are related by the simple: mean = (min+max+mode)/3
};

TriangularVariableImpl::TriangularVariableImpl() 
  : m_min(0), m_max(1), m_mode(0.5) { }
  
TriangularVariableImpl::TriangularVariableImpl(double s, double l, double mean) 
  : m_min(s), m_max(l), m_mode(3.0*mean-s-l) { }
  
TriangularVariableImpl::TriangularVariableImpl(const TriangularVariableImpl& c) 
  : RandomVariableBase(c), m_min(c.m_min), m_max(c.m_max), m_mode(c.m_mode) { }

double TriangularVariableImpl::GetValue()
{
  if(!m_generator)
    {
      m_generator = new RngStream();
    }
  double u = m_generator->RandU01();
  if(u <= (m_mode - m_min) / (m_max - m_min) )
    {
      return m_min + sqrt(u * (m_max - m_min) * (m_mode - m_min) );
    }
  else
    {
      return m_max - sqrt( (1-u) * (m_max - m_min) * (m_max - m_mode) );
    }
}

RandomVariableBase* TriangularVariableImpl::Copy() const
{
  return new TriangularVariableImpl(*this);
}

TriangularVariable::TriangularVariable()
  : RandomVariable (TriangularVariableImpl ())
{}
TriangularVariable::TriangularVariable(double s, double l, double mean)
  : RandomVariable (TriangularVariableImpl (s,l,mean))
{}


std::ostream &operator << (std::ostream &os, const RandomVariable &var)
{
  RandomVariableBase *base = var.Peek ();
  ConstantVariableImpl *constant = dynamic_cast<ConstantVariableImpl *> (base);
  if (constant != 0)
    {
      os << "Constant:" << constant->GetValue ();
      return os;
    }
  UniformVariableImpl *uniform = dynamic_cast<UniformVariableImpl *> (base);
  if (uniform != 0)
    {
      os << "Uniform:" << uniform->GetMin () << ":" << uniform->GetMax ();
      return os;
    }
  // XXX: support other distributions
  os.setstate (std::ios_base::badbit);
  return os;
}
std::istream &operator >> (std::istream &is, RandomVariable &var)
{
  std::string value;
  is >> value;
  std::string::size_type tmp;
  tmp = value.find (":");
  if (tmp == std::string::npos)
    {
      is.setstate (std::ios_base::badbit);
      return is;
    }
  std::string type = value.substr (0, tmp);
  value = value.substr (tmp + 1, value.npos);
  if (type == "Constant")
    {
      istringstream iss (value);
      double constant;
      iss >> constant;
      var = ConstantVariable (constant);
    }
  else if (type == "Uniform")
    {
      if (value.size () == 0)
        {
          var = UniformVariable ();
        }
      else
        {
          tmp = value.find (":");
          if (tmp == value.npos)
            {
              NS_FATAL_ERROR ("bad Uniform value: " << value);
            }
          istringstream issA (value.substr (0, tmp));
          istringstream issB (value.substr (tmp + 1, value.npos));
          double a, b;
          issA >> a;
          issB >> b;
          var = UniformVariable (a, b);
        }
    }
  else
    {
      NS_FATAL_ERROR ("RandomVariable deserialization not implemented for " << type);
      // XXX: support other distributions.
    }
  return is;
}



}//namespace ns3

