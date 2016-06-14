#ifndef DELETE_HPP_178D0FB21EA211E68887BB3E8C9D9CBB
#define DELETE_HPP_178D0FB21EA211E68887BB3E8C9D9CBB

#include <memory>
#include <cstdlib>

namespace pj {

template<void (*fun)(void*)>
struct fun_delete
{
    void operator () ( void* p ) { (*fun)( p ); }
};

typedef fun_delete<std::free> malloc_delete;

template<typename T>
using unique_cptr = std::unique_ptr<T, malloc_delete>;

}

#endif // DELETE_HPP_178D0FB21EA211E68887BB3E8C9D9CBB
