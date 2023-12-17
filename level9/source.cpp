#include <cstring>
#include <cstdlib>

class N
{
private:
    // int vtable;
    char annotation[100];
    int nbr;

public:
    N(int val) : nbr(val) {}

    void setAnnotation(char *ann) { std::memcpy(this->annotation, ann, std::strlen(ann)); }

    virtual int operator+(N &other) { return this->nbr + other.nbr; }
    virtual int operator-(N &other) { return this->nbr - other.nbr; }
};

int main(int argc, char **argv)
{
    if (argc <= 1)
        exit(1);

    N *ptr1 = new N(5);
    N *ptr2 = new N(6);

    N &ref1 = *ptr1;
    N &ref2 = *ptr2;

    ref1.setAnnotation(argv[1]);

    return ref2 + ref1;
}
