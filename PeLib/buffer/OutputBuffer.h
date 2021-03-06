#ifndef OUTPUTBUFFER_H
#define OUTPUTBUFFER_H

#include <vector>
#include <iterator>

namespace PeLib
{
	class OutputBuffer
	{
		private:
		  std::vector<unsigned char>& m_vBuffer;
		  
		public:
		  OutputBuffer(std::vector<unsigned char>& vBuffer);
		  const unsigned char* data() const;
		  unsigned long size();

		  template<typename T>
		  OutputBuffer& operator<<(const T& value)
		  {
			const unsigned char* p = reinterpret_cast<const unsigned char*>(&value);
			std::copy(p, p + sizeof(value), std::back_inserter(m_vBuffer));
			return *this;
		  }
		  void add(const char* lpBuffer, unsigned long ulSize);
		  void reset();
	//	  void resize(unsigned int uiSize);
		//  void set(unsigned int uiPosition);

		  template<typename T>
		  void update(unsigned long ulIndex, const T& value)
		  {
			*(T*)(&m_vBuffer[ulIndex]) = value;
		  }
	};
}

#endif
