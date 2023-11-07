#include <cstring>
#include <cstdlib>
#include <iostream>

class N
{
private:
    char annotation[100];
    int value;

public:
    N(int val) : value(val) {}

    // virtual void hello() { std::cout << "Hello, World!" << std::endl; }

    virtual N operator+(const N &other) { return N(this->value + other.value); }
    virtual N operator-(const N &other) { return N(this->value - other.value); }

    void setAnnotation(char *ann) { std::memcpy(this->annotation, ann, std::strlen(ann)); }
};

int main(int argc, char **argv)
{
    if (argc <= 1)
        exit(1);

    N obj1(5);
    N obj2(6);

    obj1.setAnnotation(argv[1]);

    // N (N::*operatorPtr)(const N&) = &N::operator+;
    // (obj2.*operatorPtr)(obj1);

    typedef N (N::*VFunc)(const N&);
    VFunc func = **(VFunc**)&obj2;
    (obj2.*func)(obj1);
}
